#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pylint: disable=protected-access, import-outside-toplevel, unused-argument

import io
import json
import os
import re
import stat
import tarfile
import traceback
import zlib
from timeit import default_timer as timer

from typing import Any, Dict, IO, List, Optional, Tuple, Union

try:
    import deflate
except ImportError:
    deflate = None

try:
    from isal import isal_zlib
except ImportError:
    isal_zlib = None  # type: ignore

try:
    import PySquashfsImage
except ImportError:
    PySquashfsImage = None  # type: ignore

try:
    from PySquashfsImage import SquashFsImage
except ImportError:
    # We need to define this for @overrides and pytype, but it also is a nice documentation
    # for the expected members in PySquashfsImage.SquashFsImage.
    class SquashFsImage:  # type: ignore
        def __init__(self, fd, offset: int = 0, closefd: bool = True) -> None:
            self._sblk: Any = None

        def __iter__(self):
            pass

        def _get_compressor(self, compression_id):
            pass

        def _initialize(self):
            pass

        # These are not overridden, only called:

        def _read_block_list(self, start, offset, blocks):
            raise NotImplementedError

        def _read_fragment(self, fragment):
            raise NotImplementedError

        def _read_inode(self, start_block, offset):
            raise NotImplementedError

        def _opendir(self, block_start, offset):
            raise NotImplementedError

        def _dir_scan(self, start_block, offset):
            raise NotImplementedError


try:
    from PySquashfsImage.compressor import Compression, Compressor, compressors
except ImportError:
    Compressor = object

from .compressions import findSquashFSOffset
from .MountSource import FileInfo, MountSource
from .SQLiteIndex import SQLiteIndex, SQLiteIndexedTarUserData
from .SQLiteIndexMountSource import SQLiteIndexMountSource
from .utils import InvalidIndexError, overrides


class IsalZlibDecompressor(Compressor):
    name = "gzip"

    def __init__(self):
        self._decompress = zlib.decompress if isal_zlib is None else isal_zlib.decompress

    def uncompress(self, src, size, outsize):
        return self._decompress(src)


class LibdeflateZlibDecompressor(Compressor):
    name = "gzip"

    def __init__(self):
        self._lib = deflate

    def uncompress(self, src, size, outsize):
        # Beware: https://github.com/dcwatson/deflate/issues/41
        return self._lib.zlib_decompress(src, outsize)


class LZ4Compressor(Compressor):
    name = "lz4"

    def __init__(self):
        import lz4.block

        self._lib = lz4.block

    def uncompress(self, src, size, outsize):
        return self._lib.decompress(src, outsize)


class LZMACompressor(Compressor):
    name = "lzma"

    def __init__(self, blockSize):
        self._blockSize = blockSize
        try:
            import lzma
        except ImportError:
            from backports import lzma
        self._lib = lzma

    def uncompress(self, src, size, outsize):
        # https://github.com/plougher/squashfs-tools/blob/a04910367d64a5220f623944e15be282647d77ba/squashfs-tools/
        #   lzma_wrapper.c#L40
        # res = LzmaCompress(dest + LZMA_HEADER_SIZE, &outlen, src, size, dest,
        #                    &props_size, 5, block_size, 3, 0, 2, 32, 1);
        # https://github.com/jljusten/LZMA-SDK/blob/781863cdf592da3e97420f50de5dac056ad352a5/C/LzmaLib.h#L96
        # -> level=5, dictSize=block_size, lc=3, lp=0, pb=2, fb=32, numThreads=1
        # https://github.com/plougher/squashfs-tools/blob/a04910367d64a5220f623944e15be282647d77ba/squashfs-tools/
        #   lzma_wrapper.c#L30
        # For some reason, squashfs does not store raw lzma but adds a custom header of 5 B and 8 B little-endian
        # uncompressed size, which can be read with struct.unpack('<Q', src[5:5+8]))
        LZMA_PROPS_SIZE = 5
        LZMA_HEADER_SIZE = LZMA_PROPS_SIZE + 8
        return self._lib.decompress(
            src[LZMA_HEADER_SIZE:],
            format=self._lib.FORMAT_RAW,
            filters=[{"id": self._lib.FILTER_LZMA1, 'lc': 3, 'lp': 0, 'pb': 2, 'dict_size': self._blockSize}],
        )


class SquashFSFile(io.RawIOBase):
    def __init__(self, image, inode) -> None:
        self._image = image
        self._inode = inode

        self._offset = 0
        self._size = inode.data
        self._blockSize = image._sblk.block_size
        self._lastBlockIndex = inode.data // self._blockSize

        self._blockList = []
        self._dataToBlockOffset: Dict[int, int] = {}  # block offset may be negative (-size) for sparse blocks
        self._compressedBlockOffsets = []
        if inode.blocks:
            self._blockList = [
                block
                for block in image._read_block_list(inode.block_start, inode.block_offset, inode.blocks)
                if block != PySquashfsImage.SQUASHFS_INVALID_FRAG
            ]

            compressedBlockOffset = inode.start
            for i, block in enumerate(self._blockList):
                blockSize = self._size % self._blockSize if i == self._lastBlockIndex else self._blockSize
                assert blockSize > 0
                if block:
                    self._compressedBlockOffsets.append(compressedBlockOffset)
                    compressedBlockOffset += PySquashfsImage.SQUASHFS_COMPRESSED_SIZE_BLOCK(block)
                else:
                    # sparse file
                    self._compressedBlockOffsets.append(-blockSize)
            assert len(self._compressedBlockOffsets) == len(self._blockList)

        self._fragment = None
        if inode.frag_bytes:
            self._fragment = image._read_fragment(inode.fragment)

        self._bufferIO: Optional[IO[bytes]] = None
        self._blockIndex = 0
        self._buffer = b''
        self._refillBuffer(self._blockIndex)  # Requires self._blockList to be initialized

    def _refillBuffer(self, blockIndex: int) -> None:
        self._blockIndex = blockIndex
        self._buffer = b''

        assert self._blockIndex >= 0
        if self._blockIndex < len(self._blockList):
            block = self._blockList[self._blockIndex]
            if block:
                start = self._compressedBlockOffsets[self._blockIndex]
                self._buffer = self._image._read_data_block(start, block)
            else:
                if (self._blockIndex + 1) * self._blockSize >= self._size:
                    blockSize = max(0, self._size - self._blockIndex * self._blockSize)
                else:
                    blockSize = self._blockSize
                self._buffer = b'\0' * blockSize
        elif self._fragment and self._blockIndex == len(self._blockList):
            fragment = self._image._read_data_block(*self._fragment)
            self._buffer = fragment[self._inode.offset : self._inode.offset + self._inode.frag_bytes]

        self._bufferIO = io.BytesIO(self._buffer)

    @overrides(io.RawIOBase)
    def readinto(self, buffer):
        """Generic implementation which uses read."""
        with memoryview(buffer) as view, view.cast("B") as byteView:  # type: ignore
            readBytes = self.read(len(byteView))
            byteView[: len(readBytes)] = readBytes
        return len(readBytes)

    def read1(self, size: int = -1) -> bytes:
        if not self._bufferIO:
            raise RuntimeError("Closed file cannot be read from!")
        result = self._bufferIO.read(size)
        # An empty buffer signals the end of the file!
        if result or not self._buffer:
            return result

        self._blockIndex += 1
        self._refillBuffer(self._blockIndex)
        return self._bufferIO.read(size)

    @overrides(io.RawIOBase)
    def read(self, size: int = -1) -> bytes:
        result = bytearray()
        while size < 0 or len(result) < size:
            readData = self.read1(size if size < 0 else size - len(result))
            if not readData:
                break
            result.extend(readData)
        return bytes(result)

    @overrides(io.RawIOBase)
    def fileno(self) -> int:
        # This is a virtual Python level file object and therefore does not have a valid OS file descriptor!
        raise io.UnsupportedOperation()

    @overrides(io.RawIOBase)
    def seekable(self) -> bool:
        return True

    @overrides(io.RawIOBase)
    def readable(self) -> bool:
        return True

    @overrides(io.RawIOBase)
    def writable(self) -> bool:
        return False

    @overrides(io.RawIOBase)
    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if not self._bufferIO:
            raise RuntimeError("Closed file cannot be seeked!")

        here = self.tell()
        if whence == io.SEEK_CUR:
            offset += here
        elif whence == io.SEEK_END:
            offset += self._size

        self._offset = max(0, min(offset, self._size))
        bufferOffset = self._blockIndex * self._blockSize
        if offset < bufferOffset or offset >= bufferOffset + len(self._buffer):
            self._refillBuffer(offset // self._blockSize)  # Updates self._blockIndex!
        self._bufferIO.seek(offset - self._blockIndex * self._blockSize)

        return self.tell()

    @overrides(io.RawIOBase)
    def tell(self) -> int:
        # Returning self._blockIndex * self._blockSize + self._bufferIO.tell() will not work when we have
        # an empty buffer after trying to read past the end of the file.
        return self._offset


# https://github.com/matteomattei/PySquashfsImage/blob/e637b26b3bc6268dd589fa1439fecf99e49a565b/PySquashfsImage/__init__.py#L82
class SquashFSImage(SquashFsImage):
    """
    Contains several improvements over the base class:
     - Does not create the whole folder hierarchy in memory when only iterating over it to avoid high memory
       usage for SquashFS images with millions of files.
     - Adds seekable, streamable file object accessor that can be opened given a single number.
     - Adds thread locks around the underlying file object so that multiple file objects can be opened and used
       from multiple threads concurrently.
     - Uses libdeflate or ISA-L if installed, which a generally faster than the standard zlib.
     - Fixes lz4 support. (Merged into PySquashfsImage upstream, but not released yet.)
     - Adds lzma support. (Merged into PySquashfsImage upstream, but not released yet.)

    Beware that we are overwriting and using "private" methods starting with underscores!
    That's why we need to pin to an exact PySquashfsImage release.
    """

    @overrides(SquashFsImage)
    def __init__(self, *args, **kwargs):
        self._real_root = None
        super().__init__(*args, **kwargs)  # Calls overridden _initialize

    @overrides(SquashFsImage)
    def _get_compressor(self, compression_id):
        if compression_id == Compression.ZLIB:
            if deflate is not None:
                return LibdeflateZlibDecompressor()
            if isal_zlib is not None:
                return IsalZlibDecompressor()
        if compression_id == Compression.LZ4:
            return LZ4Compressor()
        if compression_id == Compression.LZMA:
            return LZMACompressor(self._sblk.block_size)
        if compression_id not in compressors:
            raise ValueError("Unknown compression method " + compression_id)
        return compressors[compression_id]()

    @overrides(SquashFsImage)
    def _initialize(self):
        self._fd.seek(self._offset)
        self._read_super()
        self._read_uids_guids()
        self._read_fragment_table()
        self._read_xattrs_from_disk()
        # Moved self._root initialization into a property and _generate_root

    def _generate_root(self):
        root_block = PySquashfsImage.SQUASHFS_INODE_BLK(self._sblk.root_inode)
        root_offset = PySquashfsImage.SQUASHFS_INODE_OFFSET(self._sblk.root_inode)
        self._real_root = self._dir_scan(root_block, root_offset)

    @staticmethod
    def _join_inode_offset(start_block, offset):
        assert start_block < 2**32
        assert offset < 2**16
        return (start_block << 16) + offset

    @staticmethod
    def _split_inode_offset(inode_offset):
        return inode_offset >> 16, inode_offset & 0xFFFF

    def read_inode(self, inode_offset):
        """Newly added function over SquashFsImage that adds an accessor via a simple integer."""
        return self._read_inode(*self._split_inode_offset(inode_offset))

    @overrides(SquashFsImage)
    def __iter__(self):  # -> PySquashfsImage.file.File
        """
        Performance improved function over PySquashfsImage.__iter__ that generates data on demand instead
        of keeping all metadata in memory and returning a generator over that.
        """
        root_block = PySquashfsImage.SQUASHFS_INODE_BLK(self._sblk.root_inode)
        root_offset = PySquashfsImage.SQUASHFS_INODE_OFFSET(self._sblk.root_inode)
        root_inode_offset, root_directory = self._open_directory(root_block, root_offset)
        yield root_inode_offset, root_directory
        yield from self._recursive_inodes_iterator(root_directory)

    def _open_directory(self, start_block, offset, parent=None, name=None):
        directory = self._opendir(start_block, offset)
        if parent is not None:
            directory._parent = parent
        if name is not None:
            directory._name = name
        return self._join_inode_offset(start_block, offset), directory

    def _recursive_inodes_iterator(self, directory):  # -> PySquashfsImage.file.File
        for entry in directory.entries:
            start_block = entry["start_block"]
            offset = entry["offset"]
            if entry["type"] == PySquashfsImage.Type.DIR:
                inode_offset, subdirectory = self._open_directory(start_block, offset, directory, entry["name"])
                yield inode_offset, subdirectory
                yield from self._recursive_inodes_iterator(subdirectory)
            else:
                inode = self._read_inode(start_block, offset)
                cls = PySquashfsImage.filetype[entry["type"]]
                yield self._join_inode_offset(start_block, offset), cls(self, inode, entry["name"], directory)

    @property
    def _root(self):
        if self._real_root is None:
            self._generate_root()
        return self._real_root

    @_root.setter
    def _root(self, value):
        # super().__init__ will initialize it to None but super()._initialize should not be called!
        assert value is None

    def open(self, inode):
        return SquashFSFile(self, inode)


class SquashFSMountSource(SQLiteIndexMountSource):
    def __init__(
        self,
        # fmt: off
        fileOrPath             : Union[str, IO[bytes]],
        writeIndex             : bool                      = False,
        clearIndexCache        : bool                      = False,
        indexFilePath          : Optional[str]             = None,
        indexFolders           : Optional[List[str]]       = None,
        encoding               : str                       = tarfile.ENCODING,
        verifyModificationTime : bool                      = False,
        printDebug             : int                       = 0,
        indexMinimumFileCount  : int                       = 1000,
        transform              : Optional[Tuple[str, str]] = None,
        **options
        # fmt: on
    ) -> None:
        self.rawFileObject = open(fileOrPath, 'rb') if isinstance(fileOrPath, str) else fileOrPath
        self.rawFileObject.seek(0)
        offset = findSquashFSOffset(self.rawFileObject)
        if offset < 0:
            raise ValueError("Not a valid SquashFS image!")

        # fmt: off
        self.image                  = SquashFSImage(self.rawFileObject, offset=offset)
        self.archiveFilePath        = fileOrPath if isinstance(fileOrPath, str) else None
        self.encoding               = encoding
        self.verifyModificationTime = verifyModificationTime
        self.printDebug             = printDebug
        self.options                = options
        self.transformPattern       = transform
        # fmt: on

        self.transform = (
            (lambda x: re.sub(self.transformPattern[0], self.transformPattern[1], x))
            if isinstance(self.transformPattern, (tuple, list)) and len(self.transformPattern) == 2
            else (lambda x: x)
        )

        super().__init__(
            SQLiteIndex(
                indexFilePath,
                indexFolders=indexFolders,
                archiveFilePath=self.archiveFilePath,
                encoding=self.encoding,
                checkMetadata=self._checkMetadata,
                printDebug=self.printDebug,
                indexMinimumFileCount=indexMinimumFileCount,
                backendName='SquashFSMountSource',
            ),
            clearIndexCache=clearIndexCache,
        )

        isFileObject = not isinstance(fileOrPath, str)

        if self.index.indexIsLoaded():
            # self._loadOrStoreCompressionOffsets()  # load
            self.index.reloadIndexReadOnly()
        else:
            # Open new database when we didn't find an existing one.
            # Simply open in memory without an error even if writeIndex is True but when not indication
            # for a index file location has been given.
            if writeIndex and (indexFilePath or not isFileObject):
                self.index.openWritable()
            else:
                self.index.openInMemory()

            self._createIndex()
            # self._loadOrStoreCompressionOffsets()  # store
            if self.index.indexIsLoaded():
                self._storeMetadata()
                self.index.reloadIndexReadOnly()

    def _storeMetadata(self) -> None:
        argumentsToSave = ['encoding', 'transformPattern']
        argumentsMetadata = json.dumps({argument: getattr(self, argument) for argument in argumentsToSave})
        self.index.storeMetadata(argumentsMetadata, self.archiveFilePath)

    def _convertToRow(self, inodeOffset: int, info: "PySquashfsImage.file.File") -> Tuple:  # type: ignore
        # Note that PySquashfsImage.file.Directory inherits from file.File, i.e., info can also be a directory.
        mode = 0o555 | (stat.S_IFDIR if info.is_dir else stat.S_IFREG)
        mtime = info.time

        linkname = ""
        if info.is_symlink:
            linkname = info.readlink()
            mode = 0o555 | stat.S_IFLNK

        path, name = SQLiteIndex.normpath(self.transform(info.path)).rsplit("/", 1)

        # Currently unused. Squashfs files are stored in multiple blocks, so a single offset is insufficient.
        dataOffset = 0

        # SquashFS also returns non-zero sizes for directory, FIFOs, symbolic links, and device files
        fileSize = info.size if info.is_file else 0

        # fmt: off
        fileInfo : Tuple = (
            path              ,  # 0  : path
            name              ,  # 1  : file name
            inodeOffset       ,  # 2  : header offset
            dataOffset        ,  # 3  : data offset
            fileSize          ,  # 4  : file size
            mtime             ,  # 5  : modification time
            mode              ,  # 6  : file mode / permissions
            0                 ,  # 7  : TAR file type. Currently unused. Overlaps with mode
            linkname          ,  # 8  : linkname
            0                 ,  # 9  : user ID
            0                 ,  # 10 : group ID
            False             ,  # 11 : is TAR (unused?)
            False             ,  # 12 : is sparse
        )
        # fmt: on

        return fileInfo

    def _createIndex(self) -> None:
        if self.printDebug >= 1:
            print(f"Creating offset dictionary for {self.archiveFilePath} ...")
        t0 = timer()

        self.index.ensureIntermediaryTables()

        # TODO Doing this in a chunked manner with generators would make it work better for large archives.
        fileInfos = []
        for inodeOffset, info in self.image:
            fileInfos.append(self._convertToRow(inodeOffset, info))
        self.index.setFileInfos(fileInfos)

        # Resort by (path,name). This one-time resort is faster than resorting on each INSERT (cache spill)
        if self.printDebug >= 2:
            print("Resorting files by path ...")

        self.index.finalize()

        t1 = timer()
        if self.printDebug >= 1:
            print(f"Creating offset dictionary for {self.archiveFilePath} took {t1 - t0:.2f}s")

    @overrides(SQLiteIndexMountSource)
    def __exit__(self, exception_type, exception_value, exception_traceback):
        super().__exit__(exception_type, exception_value, exception_traceback)
        self.rawFileObject.close()
        self.image.close()

    @overrides(MountSource)
    def open(self, fileInfo: FileInfo, buffering=-1) -> IO[bytes]:
        # The buffering is ignored for now because SquashFS has an inherent buffering based on the block size
        # configured in the SquashFS image. It probably makes no sense to reduce or increase that buffer size.
        # Decreasing may reduce memory usage, but with Python and other things, memory usage is not a priority
        # in ratarmount as long as it is bounded for very large archives.
        assert fileInfo.userdata
        extendedFileInfo = fileInfo.userdata[-1]
        assert isinstance(extendedFileInfo, SQLiteIndexedTarUserData)
        return self.image.open(self.image.read_inode(extendedFileInfo.offsetheader))

    @overrides(MountSource)
    def statfs(self) -> Dict[str, Any]:
        blockSize = 512
        try:
            blockSize = os.fstat(self.rawFileObject.fileno()).st_blksize
        except Exception:
            pass

        blockSize = max(blockSize, self.image._sblk.block_size)
        return {
            'f_bsize': blockSize,
            'f_frsize': blockSize,
            'f_bfree': 0,
            'f_bavail': 0,
            'f_ffree': 0,
            'f_favail': 0,
            'f_namemax': 256,
        }

    def _tryToOpenFirstFile(self):
        # Get first row that has the regular file bit set in mode (stat.S_IFREG == 32768 == 1<<15).
        result = self.index.getConnection().execute(
            f"""SELECT path,name {SQLiteIndex.FROM_REGULAR_FILES} ORDER BY "offsetheader" ASC LIMIT 1;"""
        )
        if not result:
            return
        firstFile = result.fetchone()
        if not firstFile:
            return

        if self.printDebug >= 2:
            print(
                "[Info] The index contains no backend name. Therefore, will try to open the first file as "
                "an integrity check."
            )
        try:
            fileInfo = self.getFileInfo(firstFile[0] + '/' + firstFile[1])
            if not fileInfo:
                return

            with self.open(fileInfo) as file:
                file.read(1)
        except Exception as exception:
            if self.printDebug >= 2:
                print("[Info] Trying to open the first file raised an exception:", exception)
            if self.printDebug >= 3:
                traceback.print_exc()
            raise InvalidIndexError("Integrity check of opening the first file failed.") from exception

    def _checkMetadata(self, metadata: Dict[str, Any]) -> None:
        """Raises an exception if the metadata mismatches so much that the index has to be treated as incompatible."""

        if 'tarstats' in metadata:
            if not self.archiveFilePath:
                raise InvalidIndexError("Archive contains file stats but cannot stat real archive!")

            storedStats = json.loads(metadata['tarstats'])
            archiveStats = os.stat(self.archiveFilePath)

            if hasattr(archiveStats, "st_size") and 'st_size' in storedStats:
                if archiveStats.st_size < storedStats['st_size']:
                    raise InvalidIndexError(
                        f"Archive for this SQLite index has shrunk in size from "
                        f"{storedStats['st_size']} to {archiveStats.st_size}"
                    )

            # Only happens very rarely, e.g., for more recent files with the same size.
            if (
                self.verifyModificationTime
                and hasattr(archiveStats, "st_mtime")
                and 'st_mtime' in storedStats
                and archiveStats.st_mtime != storedStats['st_mtime']
            ):
                raise InvalidIndexError(
                    f"The modification date for the archive file {storedStats['st_mtime']} "
                    f"to this SQLite index has changed ({str(archiveStats.st_mtime)})",
                )

        if 'arguments' in metadata:
            SQLiteIndex.checkMetadataArguments(
                json.loads(metadata['arguments']), self, argumentsToCheck=['encoding', 'transformPattern']
            )

        if 'backendName' not in metadata:
            self._tryToOpenFirstFile()