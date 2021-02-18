from conans import ConanFile, CMake, tools


class VanetzaConan(ConanFile):
    name = "Vanetza"
    url = "https://github.com/riebl/vanetza"
    license = "LGPL-3.0-or-later"
    settings = "os", "compiler", "build_type", "arch"
    requires = \
        "boost/1.75.0", \
        "cryptopp/8.4.0", \
        "geographiclib/1.51", \
        "openssl/1.1.1i"
    generators = "cmake"
    options = {
        "fPIC": [True, False],
        "shared": [True, False],
        "testing": [True, False],
    }
    default_options = {
        "fPIC": True,
        "shared": False,
        "testing": True,
    }

    def _configure_cmake(self):
        cmake = CMake(self)
        cmake.configure(defs={
            "BUILD_SHARED_LIBS": self.options.shared,
            "BUILD_TESTS": self.options.testing,
        })
        return cmake

    def set_version(self):
        git = tools.Git(folder=self.recipe_folder)
        self.version = git.get_commit()[0:8]
        if not git.is_pristine():
            self.version += "-dirty"

    def configure(self):
        tools.check_min_cppstd(self, "11")
        if self.settings.compiler == 'Visual Studio':
            del self.options.fPIC

    def build(self):
        cmake = self._configure_cmake()
        cmake.build()
        if self.options.testing:
            cmake.test()

    def package(self):
        cmake = self._configure_cmake()
        cmake.install()

    def package_info(self):
        libs = ['access', 'asn1', 'asn1_its', 'asn1_pki', 'asn1_security', 'asn1_support',
                'btp', 'common', 'dcc', 'facilities', 'geonet', 'gnss', 'net', 'security']
        self.cpp_info.libs = ['vanetza_' + lib for lib in libs]
