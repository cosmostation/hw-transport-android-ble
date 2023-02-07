package com.ledger.live.ble.app

import com.ledger.live.ble.BleManager
import com.ledger.live.ble.extension.fromHexStringToBytes
import com.ledger.live.ble.extension.toHexString

class BleCosmosHelper {
    companion object {
        private const val CHUNK_SIZE = 250;
        private const val CLA = 0x55;
        private const val INS_SIGN_SECP256K1 = 0x02;
        private const val INS_GET_ADDR_SECP256K1 = 0x04;
        private const val PAYLOAD_TYPE_INIT = 0x00;
        private const val PAYLOAD_TYPE_ADD = 0x01;
        private const val PAYLOAD_TYPE_LAST = 0x02;
        private const val SW_OK = "9000";
        private const val SW_CANCEL = "6986";
        private const val SW_UNKNOWN = "9999";

        fun getAddress(
            bleManager: BleManager,
            hrp: String = "cosmos",
            hdPath: String = "44'/118'/0'/0/0",
            listener: GetAddressListener
        ) {
            if (!bleManager.isConnected) {
                return
            }

            val pathBytes = serializeHRP(hrp) + serializePath(hdPath)
            val byteArray = byteArrayOf(
                CLA.toByte(), INS_GET_ADDR_SECP256K1.toByte(), 0.toByte(), 0.toByte()
            ) + pathBytes.size.toByte() + pathBytes

            bleManager.send(apduHex = byteArray.toHexString(), onError = {
                listener.error(SW_UNKNOWN, it)
            }, onSuccess = {
                val resultCode = it.substring(it.length - 4, it.length)
                if (resultCode == SW_OK) {
                    val address = String(it.substring(66, it.length - 4).fromHexStringToBytes())
                    val pubKey = it.substring(0, 66).fromHexStringToBytes()
                    listener.success(address, pubKey)
                } else {
                    listener.error(resultCode, it.substring(0, it.length - 4))
                }

            })
        }

        fun sign(
            bleManager: BleManager,
            hdPath: String = "44'/118'/0'/0/0",
            message: String,
            listener: SignListener
        ) {
            val serializedPath = serializePath(hdPath)
            val chunks = mutableListOf<ByteArray>()
            chunks.add(serializedPath)
            val buffer = message.toByteArray()
            buffer.iterator().asSequence().chunked(CHUNK_SIZE).forEach {
                chunks.add(it.toByteArray())
            }

            for ((index, value) in chunks.withIndex()) {
                when (index) {
                    0 -> {
                        bleManager.send(makeSignChunkBytes(value, PAYLOAD_TYPE_INIT).toHexString())
                    }
                    chunks.count() - 1 -> {
                        val apduHex = makeSignChunkBytes(value, PAYLOAD_TYPE_LAST).toHexString()
                        bleManager.send(apduHex = apduHex, onError = {
                            listener.error(SW_UNKNOWN, it)
                        }, onSuccess = {
                            val resultCode = it.substring(it.length - 4, it.length)
                            if (resultCode == SW_OK) {
                                val signed = it.substring(0, it.length - 4).fromHexStringToBytes()
                                listener.success(signed)
                            } else {
                                listener.error(resultCode, it.substring(0, it.length - 4))
                            }
                        })
                    }
                    else -> {
                        bleManager.send(makeSignChunkBytes(value, PAYLOAD_TYPE_ADD).toHexString())
                    }
                }

            }
        }

        private fun serializePath(hdPath: String): ByteArray {
            val paths = hdPath.split("/")
            var pathBytes = byteArrayOf()
            paths.forEach { path ->
                val regex = Regex("(\\d+)([hH']?)")
                val matchResult = regex.find(path)
                matchResult?.let { match ->
                    var value = 0L
                    match.groups[1]?.let {
                        value += it.value.toLong()
                    }
                    match.groups[2]?.let {
                        if (listOf("h", "H", "'").contains(it.value)) {
                            value += 0x80000000
                        }
                    }
                    pathBytes += ByteArray(4) { i -> (value shr (i * 8)).toByte() }
                }
            }
            return pathBytes
        }

        private fun serializeHRP(hrp: String): ByteArray {
            var hrpBytes = byteArrayOf()
            hrpBytes += hrp.length.toByte()
            hrpBytes += hrp.toByteArray()
            return hrpBytes
        }

        private fun makeSignChunkBytes(chunkBytes: ByteArray, payload: Int): ByteArray {
            return byteArrayOf(
                CLA.toByte(), INS_SIGN_SECP256K1.toByte(), payload.toByte(), 0.toByte()
            ) + chunkBytes.size.toByte() + chunkBytes
        }
    }

    interface GetAddressListener {
        fun success(address: String, pubKey: ByteArray)
        fun error(code: String, message: String)
    }

    interface SignListener {
        fun success(signature: ByteArray)
        fun error(code: String, message: String)
    }
}