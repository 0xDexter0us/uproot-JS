package com.dexter0us.uprootJS.ui

import com.dexter0us.uprootJS.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import net.miginfocom.swing.MigLayout
import java.awt.*
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import java.awt.image.BufferedImage
import java.io.File
import java.net.URI
import javax.swing.*

class UprootJSUI : JFrame("uproot-JS"), ActionListener {
    private var chooser = JFileChooser()
    private var locationSelector = JButton()
    private var saveButton = JButton()
    private var twitterButton = JButton()
    private var githubButton = JButton()
    private var blogButton = JButton()
    private var kofiButton = JButton()
    private var folderLocation = JTextField()
    private val progressBar = JProgressBar()
    private val pwd = System.getProperty("user.dir")

    init {

//      Top Panel (Header) ----------------------------------------------------------


        val heading = JLabel().apply {
            text = "uproot-JS"
            font = font.deriveFont(30f).deriveFont(Font.BOLD)
        }

        val tagline = JLabel().apply {
            text = "Extract inScope JavaScript Files From Burp Suite."
            font = font.deriveFont(16f).deriveFont(Font.ITALIC)
        }


//      Main Panel (Body) ========================================================


        locationSelector = JButton("...")
        locationSelector.addActionListener(this)

        val saveImage = loadImage("save.png")
        when {
            saveImage != null -> {
                saveButton = JButton("Save JS Files", saveImage)
                saveButton.componentOrientation = ComponentOrientation.RIGHT_TO_LEFT
                saveButton.iconTextGap = 7
            }
            else -> saveButton = JButton("Save JS Files")
        }
        saveButton.addActionListener(this)

        progressBar.apply {
            minimum = 0
            maximum = historySize
            isStringPainted = true
            value = 0
        }


//      Contact Panel (Footer) ========================================================

        val twitterImage = loadImage("twitter.png")
        when {
            twitterImage != null -> {
                twitterButton = JButton("Follow me on Twitter", twitterImage)
                twitterButton.componentOrientation = ComponentOrientation.RIGHT_TO_LEFT
                twitterButton.iconTextGap = 3
            }
            else -> twitterButton = JButton("Follow me on Twitter")
        }
        twitterButton.addActionListener(this)


        val githubImage = loadImage("github.png")
        when {
            githubImage != null -> {
                githubButton = JButton("View Project on Github", githubImage)
                githubButton.componentOrientation = ComponentOrientation.RIGHT_TO_LEFT
                githubButton.iconTextGap = 3
            }
            else -> githubButton = JButton("View Project on Github")
        }
        githubButton.addActionListener(this)


        val blogImage = loadImage("blog.png")
        when {
            blogImage != null -> {
                blogButton = JButton("Checkout my Blog", blogImage)
                blogButton.componentOrientation = ComponentOrientation.RIGHT_TO_LEFT
                blogButton.iconTextGap = 3
            }
            else -> blogButton = JButton("Checkout my Blog")
        }
        blogButton.addActionListener(this)


        val kofiImage = loadImage("ko-fi.png")
        when {
            kofiImage != null -> {
                kofiButton = JButton("Support Project on Ko-Fi", kofiImage)
                kofiButton.componentOrientation = ComponentOrientation.RIGHT_TO_LEFT
                kofiButton.iconTextGap = 3
            }
            else -> kofiButton = JButton("Buy me a Coffee")
        }
        kofiButton.addActionListener(this)


        val northPanel = JPanel().apply {
            layout = MigLayout("align center")
            border = BorderFactory.createEmptyBorder(3, 5, 0, 5)
            add(heading, "bottom, center, span, wrap")
            add(tagline, "top, center, span, wrap")
        }

        val bodyPanel = JPanel().apply {
            layout = MigLayout()
            border = BorderFactory.createEmptyBorder(0, 10, 0, 10)

            //add(JSeparator(SwingConstants.HORIZONTAL), "grow, wrap")
            add(JLabel("Location:"), "right")
            add(folderLocation, "growx, w 300!, h 30!")
            add(locationSelector, "wrap, h 30!")
            add(JSeparator(SwingConstants.HORIZONTAL), "")
            add(saveButton, "span, center, w 200!, h 35!")
            add(progressBar, "span, center, growx, h 20!")

        }

        val southPanel = JPanel().apply {
            layout = MigLayout("align center")
            border = BorderFactory.createEmptyBorder(2, 0, 10, 0)

            add(JLabel("Created with <3 by Dexter0us"), "span, align center, wrap")
            add(twitterButton, "w 230!, h 35!")
            add(githubButton, "w 230!, h 35!, wrap")
            add(blogButton, "w 230!, h 35!")
            add(kofiButton, "w 230!, h 35!, wrap")
        }

        this.also {
            layout = MigLayout("align center")

            add(northPanel, "dock north")
            add(JSeparator(SwingConstants.HORIZONTAL), "wrap")
            add(bodyPanel, "wrap, align center")
            add(JSeparator(SwingConstants.HORIZONTAL), "wrap")
            add(southPanel, "dock south")

            defaultCloseOperation = DISPOSE_ON_CLOSE
            isResizable = false
            setSize(600, 500)
            isVisible = true
        }
    }


    override fun actionPerformed(e: ActionEvent?) {
        when (e?.source) {
            locationSelector -> folderSelector()
            saveButton -> {
                progressBar.value = 0
                saveButton.isEnabled = false
                cursor = Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR)
                GlobalScope.launch(Dispatchers.Swing) {
                    currJob?.cancel()

                    val processResult = HistoryProcessor().historyParser(folderLocation.text)
                    currJob = processResult.job
                    for (y in processResult.resultChannel) {
                        progressBar.maximum = historySize - 5
                        progressBar.value = y
                    }
                    progressBar.value = historySize
                    saveButton.isEnabled = true
                    cursor = Cursor.getDefaultCursor()
                }
            }
            twitterButton -> openInBrowser("https://twitter.com/0xDexter0us")
            githubButton -> openInBrowser("https://github.com/0xDexter0us/Scavenger")
            blogButton -> openInBrowser("https://dexter0us.com/")
            kofiButton -> openInBrowser("https://ko-fi.com/dexter0us")
        }
    }

// Credits to CoreyD97 for this idea and function

    private fun loadImage(filename: String): ImageIcon? {
        val cldr = this.javaClass.classLoader
        val imageURLMain = cldr.getResource(filename)
        if (imageURLMain != null) {
            val scaled = ImageIcon(imageURLMain).image.getScaledInstance(30, 30, Image.SCALE_SMOOTH)
            val scaledIcon = ImageIcon(scaled)
            val bufferedImage = BufferedImage(30, 30, BufferedImage.TYPE_INT_ARGB)
            val g = bufferedImage.graphics as Graphics2D
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            g.drawImage(scaledIcon.image, null, null)
            return ImageIcon(bufferedImage)
        }
        return null
    }


    private fun folderSelector() {
        chooser = JFileChooser().apply {
            currentDirectory = File(pwd)
            dialogTitle = "Select Folder"
            fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
            isAcceptAllFileFilterUsed = false
            val response = showSaveDialog(null)

            when (response) {
                JFileChooser.APPROVE_OPTION -> {
                    folderLocation.text = File(selectedFile.absolutePath).toString()
                }
                else -> {
                    folderLocation.text = currentDirectory.toString()
                }
            }
        }
    }

    private fun openInBrowser(url: String) {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            Desktop.getDesktop().browse(URI(url))
        } else {
            alertBox("Unable to open browser.\n Visit: $url")
        }
    }

    private fun alertBox(str: String) {
        JOptionPane.showMessageDialog(this, str, "uprootJS", JOptionPane.PLAIN_MESSAGE)
    }

}