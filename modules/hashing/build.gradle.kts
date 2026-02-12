import com.vanniktech.maven.publish.SonatypeHost
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    alias(libs.plugins.dokka)
    alias(libs.plugins.publishing)
}

group = "com.wannaverse"
version = "0.0.1"

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget = JvmTarget.JVM_11
        }
        publishLibraryVariants("release")
        publishLibraryVariantsGroupedByFlavor = true
    }

    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
        }
        androidMain.dependencies {
            libs.bcprov.jdk18on
        }
    }
}

android {
    namespace = "com.wannaverse.crypto.hashing"
    compileSdk = libs.versions.android.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

mavenPublishing {
    publishToMavenCentral(SonatypeHost.CENTRAL_PORTAL)

    signAllPublications()

    coordinates(group.toString(), "kmp-crypto-hashing", version.toString())

    pom {
        name = "kmp-crypto-hashing"
        description = "A cryptographic hashing library for Kotlin Multiplatform"
        inceptionYear = "2025"
        url = "https://github.com/WannaverseOfficial/kmp-crypto"
        licenses {
            license {
                name = "MIT License"
                url = "https://opensource.org/licenses/MIT"
                distribution = "https://opensource.org/licenses/MIT"
            }
        }
        developers {
            developer {
                id = "Wannaverse"
                name = "wannaverse"
                url = "https://github.com/WannaverseOfficial"
            }
        }
        scm {
            url = "https://github.com/WannaverseOfficial/kmp-crypto"
            connection = "scm:git:git://github.com/WannaverseOfficial/kmp-crypto.git"
            developerConnection = "scm:git:ssh://git@github.com/WannaverseOfficial/kmp-crypto.git"
        }
    }
}

tasks.dokkaHtml {
    outputDirectory.set(file("${rootDir}/docs/hashing"))
}