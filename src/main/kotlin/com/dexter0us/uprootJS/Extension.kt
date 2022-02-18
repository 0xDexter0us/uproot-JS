package com.dexter0us.uprootJS

import burp.*
import com.dexter0us.uprootJS.ui.UprootJSUI
import java.io.PrintWriter
import javax.swing.*


open class Extension : IBurpExtender, IExtensionStateListener {
    companion object{
        const val pluginName = "uproot-JS"
        const val version = "1.0"
    }

    private var urjsUnload = false
    private var burpMenu: JMenuBar? = null
    private var urjsMenu: JMenu? = null

    override fun registerExtenderCallbacks(_callbacks: IBurpExtenderCallbacks) {
        callbacks = _callbacks
        helpers = _callbacks.helpers
        stdout = PrintWriter(callbacks.stdout, true)
        stderr = PrintWriter(callbacks.stderr, true)

        callbacks.apply {
            setExtensionName(pluginName)
            registerExtensionStateListener { extensionUnloaded() }
        }

        console("$pluginName v$version Loaded")

        SwingUtilities.invokeLater {
            try {
                burpMenu = getBurpFrame()!!.jMenuBar
                urjsMenu = JMenu("uproot-JS")
                val listCustomTagsMenu = JMenuItem("Save JS Files")
                listCustomTagsMenu.addActionListener { UprootJSUI() }
                urjsMenu!!.add(listCustomTagsMenu)
                burpMenu!!.add(urjsMenu)
            } catch (e: Exception) {
                e.printStackTrace()
            }

        }
    }

    open fun getBurpFrame(): JFrame? {
        for (frame in JFrame.getFrames()) {
            if (frame.isVisible && frame.title.startsWith("Burp Suite")) {
                return frame as JFrame?
            }
        }
        return null
    }

    override fun extensionUnloaded() {
        stdout.println("UprootJS unloaded")
        urjsUnload = true
        burpMenu?.remove(urjsMenu)
        burpMenu?.repaint()
        currJob?.cancel()
    }

 }