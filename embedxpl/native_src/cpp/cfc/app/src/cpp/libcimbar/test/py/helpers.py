from os.path import dirname, join, realpath
from tempfile import TemporaryDirectory

CIMBAR_SRC = realpath(join(dirname(realpath(__file__)), '..', '..'))
BIN_DIR = join(CIMBAR_SRC, 'dist', 'bin')


class TestDirMixin:
    def setUp(self):
        self.working_dir = TemporaryDirectory()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        with self.working_dir:
            pass
