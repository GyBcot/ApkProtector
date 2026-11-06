plugins {
    alias(libs.plugins.kotlin.jvm) apply false
}

allprojects {
    group = "com.rscoders"
    version = "1.5.0"
}

subprojects {
    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
            freeCompilerArgs.add("-Xjsr305=strict")
        }
    }
}
