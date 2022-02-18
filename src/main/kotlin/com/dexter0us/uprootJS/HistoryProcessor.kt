package com.dexter0us.uprootJS


import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import org.apache.commons.io.FileUtils
import org.apache.commons.io.FilenameUtils
import java.io.File
import java.net.URL
import java.util.*

class HistoryProcessor {

    fun historyParser(fileLocation: String): ProcessResult {
        val channel = Channel<Int>()
        val job = GlobalScope.launch(Dispatchers.Default) {

            val proxyHistory = callbacks.proxyHistory
            var body = byteArrayOf()
            val urls = mutableSetOf<URL>()

            proxyHistory.forEach {

                if (counter % 20 == 0) {
                    channel.send(counter)
                }
                counter++

                val reqInfo = helpers.analyzeRequest(it.httpService, it.request)
                it.response ?: return@forEach
                val respInfo = helpers.analyzeResponse(it.response)
                val statusCode = respInfo.statusCode.toInt()

                if (
                    (callbacks.isInScope(reqInfo.url))
                    && statusCode == 200
                    && respInfo.inferredMimeType.lowercase() == "script"
                ) {

                    if (urls.contains(reqInfo.url)) return@forEach
                    urls.add(reqInfo.url)
                    try {
                        body = Arrays.copyOfRange(it.response, respInfo.bodyOffset, it.response.size)
                        writeFile(fileLocation, fileName(reqInfo.url.toString()), body)
                    } catch (e: Exception) {
                        stderr.println("Unable to save ${reqInfo.url.toString()}")
                        }
                }
            }
                channel.close()
        }
            return ProcessResult(channel, job)
    }

    val writeFile = { fileLocation: String, fileName: String, body: ByteArray ->
        val absoluteFilePath = FilenameUtils.concat(fileLocation, fileName)
        console("File: $absoluteFilePath")
        FileUtils.writeByteArrayToFile(File(absoluteFilePath), body)
        console("Saved $fileName")
    }

    private fun fileName(url: String): String {
        val index = url.lastIndexOf('/')
        return url.substring(index + 1)
    }

}




