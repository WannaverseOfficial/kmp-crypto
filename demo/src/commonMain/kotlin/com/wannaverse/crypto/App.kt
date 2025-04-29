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

            Text("" + hashed)
            Text("" + toHex)
            Text("" + fromHex)
            Text("" + isEqual)

        }
    }
}