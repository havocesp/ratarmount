#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pylint: disable=wrong-import-position
# pylint: disable=protected-access

import bz2
import concurrent.futures
import io
import os
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest  # noqa: E402

from ratarmountcore import SQLiteIndexedTar  # noqa: E402


@pytest.mark.parametrize("parallelization", [1, 2, 4])
class TestSQLiteIndexedTarParallelized:
    @staticmethod
    def _createFile(tarArchive, name, contents):
        tinfo = tarfile.TarInfo(name)
        tinfo.size = len(contents)
        tarArchive.addfile(tinfo, io.BytesIO(contents.encode()))

    @staticmethod
    def _makeFolder(tarArchive, name):
        tinfo = tarfile.TarInfo(name)
        tinfo.type = tarfile.DIRTYPE
        tarArchive.addfile(tinfo, io.BytesIO())

    @staticmethod
    def test_context_manager(parallelization):
        with SQLiteIndexedTar('tests/single-file.tar', writeIndex=False, parallelization=parallelization) as indexedTar:
            assert indexedTar.listDir('/')

    @staticmethod
    def test_tar_bz2_with_parallelization(parallelization):
        with SQLiteIndexedTar(
            "tests/2k-recursive-tars.tar.bz2",
            clearIndexCache=True,
            recursive=False,
            parallelization=parallelization,
        ) as file:
            assert file.listDir('/')
            assert file.listDir('/mimi')

            assert not file.listDir('/mimi/01995.tar')
            info = file.getFileInfo('/mimi/01995.tar')
            assert info.userdata[0].offset == 21440512

            assert not file.listDir('/mimi/00105.tar')
            info = file.getFileInfo('/mimi/00105.tar')
            assert info.userdata[0].offset == 1248256

    @staticmethod
    def test_recursive_tar_bz2_with_parallelization(parallelization):
        with SQLiteIndexedTar(
            "tests/2k-recursive-tars.tar.bz2",
            clearIndexCache=True,
            recursive=True,
            parallelization=parallelization,
        ) as file:
            assert file.listDir('/')
            assert file.listDir('/mimi')

            assert file.listDir('/mimi/01995.tar')
            info = file.getFileInfo('/mimi/01995.tar/foo')
            assert info.userdata[0].offset == 21441024

            assert file.listDir('/mimi/00105.tar')
            info = file.getFileInfo('/mimi/00105.tar/foo')
            assert info.userdata[0].offset == 1248768

    @staticmethod
    def test_index_creation_and_loading(parallelization):
        with tempfile.TemporaryDirectory() as tmpDirectory:
            oldCurrentWorkingDirectory = os.getcwd()

            # Try with a writable directory and a non-writable current working directory
            # because FUSE also changes to root after mounting and forking to background.
            for directory in [tmpDirectory, '/']:
                os.chdir(directory)
                try:
                    archiveName = 'simple.bz2'
                    indexPath = 'simple.custom.index'
                    if directory != tmpDirectory:
                        archiveName = os.path.join(tmpDirectory, archiveName)
                        indexPath = os.path.join(tmpDirectory, indexPath)

                    contents = b"Hello World!"
                    with bz2.open(archiveName, "wb") as bz2File:
                        bz2File.write(contents)

                    def testIndex(tarFileName, fileObject, indexFilePath):
                        TestSQLiteIndexedTarParallelized._test_index_creation_and_loading(
                            tarFileName, fileObject, indexFilePath, contents, parallelization
                        )

                    # States for arguments:
                    #  - file name: 3 (None, Path, ':memory:')
                    #  - archiveName: Optional[str]
                    #  - fileObject: Optional[IO]
                    # => 3*2*2 = 12 cases

                    with pytest.raises(ValueError):
                        testIndex(None, None, ':memory:')
                    with pytest.raises(ValueError):
                        testIndex(None, None, indexPath)
                    with pytest.raises(ValueError):
                        testIndex(None, None, None)

                    testIndex(archiveName, None, ':memory:')
                    testIndex(archiveName, None, indexPath)
                    testIndex(archiveName, None, None)

                    with open(archiveName, "rb") as file:
                        testIndex("tarFileName", file, ':memory:')
                        testIndex("tarFileName", file, indexPath)
                        testIndex("tarFileName", file, None)

                        testIndex(None, file, ':memory:')
                        testIndex(None, file, indexPath)
                        testIndex(None, file, None)

                finally:
                    os.chdir(oldCurrentWorkingDirectory)

    @staticmethod
    def _test_index_creation_and_loading(tarFileName, fileObject, indexFilePath, contents, parallelization):
        if indexFilePath:
            assert not os.path.exists(indexFilePath) or os.stat(indexFilePath).st_size == 0
        oldFolderContents = os.listdir('.')

        # Create index
        with SQLiteIndexedTar(
            fileObject=fileObject,
            tarFileName=tarFileName,
            writeIndex=True,
            clearIndexCache=True,
            indexFilePath=indexFilePath,
            parallelization=parallelization,
        ):
            pass

        # When opening a file object without a path or with path ':memory:',
        # no index should have been created anywhere!
        if (fileObject is not None and indexFilePath is None) or indexFilePath == ':memory:':
            assert oldFolderContents == os.listdir('.')
            return

        createdIndexFilePath = indexFilePath
        if not indexFilePath and not fileObject and tarFileName:
            createdIndexFilePath = tarFileName + '.index.sqlite'
        assert os.stat(createdIndexFilePath).st_size > 0

        # Read from index
        indexedFile = SQLiteIndexedTar(
            fileObject=fileObject,
            tarFileName=tarFileName,
            writeIndex=False,
            clearIndexCache=False,
            indexFilePath=indexFilePath,
            parallelization=parallelization,
        )

        objectName = '<file object>' if tarFileName is None else tarFileName
        expectedName = os.path.basename(tarFileName).rsplit('.', 1)[0] if fileObject is None else objectName

        finfo = indexedFile._getFileInfo("/", listDir=True)
        assert expectedName in finfo
        assert finfo[expectedName].size == len(contents)

        finfo = indexedFile.getFileInfo("/" + expectedName)
        assert finfo.size == len(contents)
        assert indexedFile.read(finfo, size=len(contents), offset=0) == contents
        assert indexedFile.read(finfo, size=3, offset=3) == contents[3:6]

        if createdIndexFilePath:
            os.remove(createdIndexFilePath)

    @staticmethod
    def test_listDir_and_fileVersions(parallelization):
        with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmpTarFile:
            with tarfile.open(name=tmpTarFile.name, mode="w:gz") as tarFile:
                createFile = TestSQLiteIndexedTarParallelized._createFile
                makeFolder = TestSQLiteIndexedTarParallelized._makeFolder

                createFile(tarFile, "./README.md", "hello world")
                makeFolder(tarFile, "./src")
                createFile(tarFile, "./src/test.sh", "echo hi")
                makeFolder(tarFile, "./dist")
                makeFolder(tarFile, "./dist/a")
                makeFolder(tarFile, "./dist/a/b")
                createFile(tarFile, "./dist/a/b/test2.sh", "echo two")

            with SQLiteIndexedTar(tmpTarFile.name, clearIndexCache=True, parallelization=parallelization) as indexedTar:
                folders = []
                files = []

                foldersToRecurse = ["/"]
                while foldersToRecurse:
                    folder = foldersToRecurse.pop()
                    for name in indexedTar.listDir(folder):
                        path = os.path.join(folder, name)
                        print(path)
                        fileInfo = indexedTar.getFileInfo(path)
                        if not fileInfo:
                            continue

                        if stat.S_ISDIR(fileInfo.mode):
                            folders.append(path)
                            foldersToRecurse.append(path)
                        else:
                            files.append(path)

                assert set(folders) == set(["/dist", "/dist/a", "/dist/a/b", "/src"])
                assert set(files) == set(["/dist/a/b/test2.sh", "/src/test.sh", "/README.md"])

                for path in folders + files:
                    assert indexedTar.fileVersions(path) == 1

    @staticmethod
    def test_open(parallelization):
        with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmpTarFile:
            repeatCount = 10000

            with tarfile.open(name=tmpTarFile.name, mode="w:gz") as tarFile:
                createFile = TestSQLiteIndexedTarParallelized._createFile
                createFile(tarFile, "increasing.dat", "".join(["0123456789"] * repeatCount))
                createFile(tarFile, "decreasing.dat", "".join(["9876543210"] * repeatCount))

            with SQLiteIndexedTar(tmpTarFile.name, clearIndexCache=True, parallelization=parallelization) as indexedTar:
                iFile = indexedTar.open(indexedTar.getFileInfo("/increasing.dat"))
                dFile = indexedTar.open(indexedTar.getFileInfo("/decreasing.dat"))

                for i in range(repeatCount):
                    try:
                        assert iFile.read(10) == b"0123456789"
                        assert dFile.read(10) == b"9876543210"
                    except AssertionError as e:
                        print("Reading failed in iteration:", i)
                        raise e

    @staticmethod
    def test_multithreaded_reading(parallelization):
        parallelism = parallelization * 6  # Need a bit more parallelism to trigger bugs easier
        with tempfile.NamedTemporaryFile(suffix=".tar.gz") as tmpTarFile, concurrent.futures.ThreadPoolExecutor(
            parallelism
        ) as pool:
            repeatCount = 10000

            with tarfile.open(name=tmpTarFile.name, mode="w:gz") as tarFile:
                createFile = TestSQLiteIndexedTarParallelized._createFile
                createFile(tarFile, "increasing.dat", "".join(["0123456789"] * repeatCount))
                createFile(tarFile, "decreasing.dat", "".join(["9876543210"] * repeatCount))

            with SQLiteIndexedTar(tmpTarFile.name, clearIndexCache=True, parallelization=parallelization) as indexedTar:

                def read_sequences(file, useIncreasing):
                    for i in range(repeatCount):
                        try:
                            if useIncreasing:
                                assert file.read(10) == b"0123456789"
                            else:
                                assert file.read(10) == b"9876543210"
                        except AssertionError as e:
                            print("Reading failed in iteration:", i)
                            raise e
                    return True

                files = [
                    indexedTar.open(indexedTar.getFileInfo(f"/{'in' if i % 2 == 0 else 'de'}creasing.dat"))
                    for i in range(parallelism)
                ]

                results = []
                for i in range(parallelism):
                    results.append(pool.submit(read_sequences, files[i], i % 2 == 0))
                for result in results:
                    result.result()

                for file in files:
                    file.close()

    @staticmethod
    def test_appending(parallelization, tmpdir):
        createFile = TestSQLiteIndexedTarParallelized._createFile
        makeFolder = TestSQLiteIndexedTarParallelized._makeFolder

        # Create a simple small TAR
        tarPath = os.path.join(tmpdir, "foo.tar")
        with tarfile.open(name=tarPath, mode="w:") as tarFile:
            createFile(tarFile, "foo", "bar")

        # Create index
        indexFilePath = os.path.join(tmpdir, "foo.tar.index")
        with SQLiteIndexedTar(
            tarFileName=tarPath,
            writeIndex=True,
            clearIndexCache=True,
            indexFilePath=indexFilePath,
            parallelization=parallelization,
        ) as indexedTar:
            assert not indexedTar.hasBeenAppendedTo
            assert indexedTar.exists("/foo")
            assert not indexedTar.exists("/bar")
            assert not indexedTar.exists("/folder")

        # Append small file to TAR
        with tarfile.open(name=tarPath, mode="a:") as tarFile:
            createFile(tarFile, "bar", "foo")

        # Create index but only go over new files
        indexFilePath = os.path.join(tmpdir, "foo.tar.index")
        with SQLiteIndexedTar(
            tarFileName=tarPath,
            writeIndex=True,
            clearIndexCache=False,
            indexFilePath=indexFilePath,
            parallelization=parallelization,
        ) as indexedTar:
            assert indexedTar.hasBeenAppendedTo
            assert indexedTar.exists("/foo")
            assert indexedTar.exists("/bar")
            assert not indexedTar.exists("/folder")

        # Append empty folder to TAR
        with tarfile.open(name=tarPath, mode="a:") as tarFile:
            makeFolder(tarFile, "folder")

        # Create index but only go over new files
        indexFilePath = os.path.join(tmpdir, "foo.tar.index")
        with SQLiteIndexedTar(
            tarFileName=tarPath,
            writeIndex=True,
            clearIndexCache=False,
            indexFilePath=indexFilePath,
            parallelization=parallelization,
        ) as indexedTar:
            assert indexedTar.hasBeenAppendedTo
            assert indexedTar.exists("/foo")
            assert indexedTar.exists("/bar")
            assert indexedTar.exists("/folder")

        # Append a sparse file
        sparsePath = os.path.join(tmpdir, "sparse")
        with open(sparsePath, "w") as file:
            pass
        os.truncate(sparsePath, 1024 * 1024)
        # The tarfile module only has read support for sparse files, therefore use GNU tar to do it
        subprocess.run(["tar", "--append", "-f", tarPath, sparsePath])

        # Create index. Because of the sparse file at the end, it might be recreated from scratch.
        indexFilePath = os.path.join(tmpdir, "foo.tar.index")
        with SQLiteIndexedTar(
            tarFileName=tarPath,
            writeIndex=True,
            clearIndexCache=False,
            indexFilePath=indexFilePath,
            parallelization=parallelization,
        ) as indexedTar:
            # assert indexedTar.hasBeenAppendedTo  # TODO
            assert indexedTar.exists("/foo")
            assert indexedTar.exists("/bar")
            assert indexedTar.exists("/folder")
