package com.wannaverse.crypto

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.wannaverse.crypto.core.Encoding.fromHex
import com.wannaverse.crypto.core.Encoding.toHex
import com.wannaverse.crypto.hashing.Argon2
import com.wannaverse.crypto.hashing.Argon2Config
import com.wannaverse.crypto.hashing.Argon2Type
import com.wannaverse.crypto.hashing.sha1
import org.jetbrains.compose.ui.tooling.preview.Preview

@Composable
@Preview
fun App() {
    MaterialTheme {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(50.dp)
        ) {


            val sample = "Hello, World!".encodeToByteArray()
            val hashed = sha1(sample)
            val toHex = toHex(hashed)
            val fromHex = fromHex(toHex)
            val isEqual = hashed.contentEquals(fromHex)

            Text("SHA1: $toHex")
            Text("Hex roundtrip: $isEqual")

            // Argon2 password hashing example
            val password = "mypassword".encodeToByteArray()
            val salt = "somesalt12345678".encodeToByteArray()
            val argon2 = Argon2()
            val argon2Hash = argon2.hash(
                password = password,
                salt = salt,
                config = Argon2Config(
                    type = Argon2Type.Argon2id,
                    hashLength = 16,
                    parallelism = 1,
                    memorySizeKB = 16,
                    iterations = 3,
                )
            )
            Text("Argon2id: ${toHex(argon2Hash)}")

        }
    }
}