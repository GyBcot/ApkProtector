package com.rscoders.core

import java.io.File

data class StepReport(
    val name: String,
    val detail: String,
)

data class HardeningResult(
    val outputApk: File,
    val originalApplicationClass: String?,
    val encryptedDexCount: Int,
    val payloadBytes: Long,
    val signed: Boolean,
    val steps: List<StepReport>,
)
