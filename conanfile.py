from conans import ConanFile


class VanetzaConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = "Boost/1.60.0@lasote/stable", "cryptopp/5.6.3@riebl/testing", "GeographicLib/1.46@riebl/testing"
    generators = "cmake"
