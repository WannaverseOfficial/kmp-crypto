package com.wannaverse.crypto.jwt

import platform.Foundation.NSDate
import platform.Foundation.timeIntervalSince1970

internal actual fun currentTimeSeconds(): Long = NSDate().timeIntervalSince1970.toLong()
