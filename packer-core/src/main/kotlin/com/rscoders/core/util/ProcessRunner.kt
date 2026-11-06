package com.rscoders.core.util

import java.io.File

data class ProcessResult(
    val command: List<String>,
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
) {
    val ok: Boolean get() = exitCode == 0

    fun orThrow(): ProcessResult {
        if (!ok) {
            throw ToolExecutionException(
                "Command failed (exit=$exitCode): ${command.joinToString(" ")}\n" +
                    "--- stdout ---\n$stdout\n--- stderr ---\n$stderr",
            )
        }
        return this
    }
}

class ToolExecutionException(message: String) : RuntimeException(message)

object ProcessRunner {
    fun run(command: List<String>, workingDir: File? = null): ProcessResult {
        val process = ProcessBuilder(command)
            .apply { if (workingDir != null) directory(workingDir) }
            .redirectErrorStream(false)
            .start()
        val out = process.inputStream.bufferedReader().readText()
        val err = process.errorStream.bufferedReader().readText()
        val code = process.waitFor()
        return ProcessResult(command, code, out, err)
    }
}
