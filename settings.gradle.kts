rootProject.name = "rscoders"

include(
    "packer-core",
    "packer-cli",
)

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}
