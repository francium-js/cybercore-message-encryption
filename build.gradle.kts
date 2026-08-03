plugins {
    id("java-library")
    alias(libs.plugins.run.paper)
}

repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}

dependencies {
    compileOnly(libs.folia.api)

    // slf4j-api already comes from folia-api on the server classpath. A second
    // copy would leave Javalin's own SLF4J logging silently unbound, so it is
    // excluded here. Jetty is not on the server classpath and must be shaded in.
    implementation(libs.javalin) {
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
}

java {
    toolchain.languageVersion = JavaLanguageVersion.of(25)
}

tasks {
    runServer {
        minecraftVersion(libs.versions.minecraft.get())
        jvmArgs("-Xms2G", "-Xmx2G")
    }

    processResources {
        val props = mapOf("version" to version)
        filesMatching("paper-plugin.yml") {
            expand(props)
        }
    }
}
