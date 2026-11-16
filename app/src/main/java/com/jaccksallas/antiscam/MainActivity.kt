package com.jaccksallas.antiscam

import android.app.Activity
import android.os.Bundle
import android.content.Intent
import android.content.ClipData
import android.graphics.Color
import android.net.Uri
import android.view.Gravity
import android.view.ViewGroup
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private val prefs by lazy { getSharedPreferences("anti_scam_local", MODE_PRIVATE) }
    private val navy = Color.rgb(15, 23, 42)
    private val blue = Color.rgb(37, 99, 235)
    private lateinit var content: LinearLayout
    private lateinit var linkField: EditText
    private lateinit var resultText: TextView
    private lateinit var nameField: EditText
    private lateinit var contactField: EditText
    private lateinit var platformField: EditText
    private lateinit var notesField: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showHome()
    }

    private fun baseScreen(titleText: String) {
        val outer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(241, 245, 249))
        }
        val header = TextView(this).apply {
            text = "JACKCSALLAS  /  $titleText"
            textSize = 19f
            setTextColor(Color.WHITE)
            setPadding(20, 22, 20, 22)
            setBackgroundColor(navy)
        }
        outer.addView(header, ViewGroup.LayoutParams(-1, -2))
        val scroll = ScrollView(this)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(18, 18, 18, 24)
        }
        scroll.addView(content)
        outer.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(outer)
    }

    private fun label(text: String) {
        content.addView(TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(Color.rgb(51, 65, 85))
            setPadding(2, 12, 2, 5)
        })
    }

    private fun field(hintText: String, multiline: Boolean = false): EditText {
        return EditText(this).apply {
            hint = hintText
            textSize = 15f
            setTextColor(Color.rgb(15, 23, 42))
            setHintTextColor(Color.GRAY)
            setPadding(12, 10, 12, 10)
            if (multiline) {
                minLines = 3
                gravity = Gravity.TOP
                inputType = android.text.InputType.TYPE_CLASS_TEXT or
                    android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                    android.text.InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            } else {
                singleLine = true
            }
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(Color.WHITE)
                cornerRadius = 14f
                setStroke(1, Color.rgb(203, 213, 225))
            }
        }
    }

    private fun button(text: String, action: () -> Unit) {
        content.addView(Button(this).apply {
            this.text = text
            isAllCaps = false
            setTextColor(Color.WHITE)
            backgroundTintList = android.content.res.ColorStateList.valueOf(blue)
            setOnClickListener { action() }
        }, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 8 })
    }

    private fun paragraph(text: String, size: Float = 14f) {
        content.addView(TextView(this).apply {
            this.text = text
            textSize = size
            setTextColor(Color.rgb(51, 65, 85))
            setPadding(2, 8, 2, 8)
        })
    }

    private fun showHome() {
        baseScreen("ANTI-SCAM")
        paragraph("Pusat pencatatan insiden penipuan dan pemeriksaan awal tautan.", 16f)
        paragraph("Data insiden disimpan lokal di perangkat ini. Aplikasi tidak mengakses pesan, kontak, atau akun secara otomatis.")
        button("Periksa tautan mencurigakan") { showLinkChecker() }
        button("Buat laporan insiden") { showIncidentForm() }
        button("Lihat bukti tersimpan") { showEvidence() }
        button("Bagikan ringkasan laporan") { shareReport() }
    }

    private fun showLinkChecker() {
        baseScreen("PEMERIKSA TAUTAN")
        paragraph("Tempel tautan yang ingin diperiksa. Pemeriksaan ini berbasis indikator lokal, bukan verifikasi reputasi internet.")
        linkField = field("https://contoh.com")
        content.addView(linkField, ViewGroup.LayoutParams(-1, -2))
        resultText = TextView(this).apply {
            text = "Hasil pemeriksaan akan muncul di sini."
            textSize = 15f
            setTextColor(navy)
            setPadding(12, 16, 12, 16)
            setBackgroundColor(Color.WHITE)
        }
        content.addView(resultText, ViewGroup.LayoutParams(-1, -2))
        button("ANALISIS TAUTAN") {
            val report = inspectUrl(linkField.text.toString().trim())
            resultText.text = report
        }
        button("Kembali") { showHome() }
    }

    private fun inspectUrl(raw: String): String {
        if (raw.isBlank()) return "Masukkan tautan terlebih dahulu."
        val normalized = if (raw.startsWith("http://") || raw.startsWith("https://")) raw else "https://$raw"
        val uri = runCatching { Uri.parse(normalized) }.getOrNull()
            ?: return "Format tautan tidak dapat dibaca."
        val host = uri.host?.lowercase(Locale.ROOT) ?: return "Host/domain tidak ditemukan. Jangan buka tautan ini sebelum diverifikasi."
        val flags = mutableListOf<String>()
        if (uri.scheme != "https") flags += "Tidak menggunakan HTTPS."
        if (host.matches(Regex("""\d{1,3}(\.\d{1,3}){3}"""))) flags += "Menggunakan alamat IP langsung sebagai host."
        if (host.startsWith("xn--") || host.contains(".xn--")) flags += "Mengandung domain Punycode yang dapat menyamarkan karakter."
        if (host.count { it == '.' } >= 4) flags += "Memiliki banyak subdomain."
        val shorteners = listOf("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy")
        if (shorteners.any { host == it || host.endsWith(".$it") }) flags += "Menggunakan layanan pemendek tautan; tujuan akhir disamarkan."
        val suspiciousWords = listOf("login", "verify", "verification", " hadiah", "hadiah", "claim", "bank", "wallet", "password", "secure", "bonus", "undian")
        val full = (host + uri.path + (uri.query ?: "")).lowercase(Locale.ROOT)
        if (suspiciousWords.any { full.contains(it.trim()) }) flags += "URL memuat kata yang sering dipakai dalam umpan phishing."
        if (flags.isEmpty()) {
            return "Tidak ditemukan indikator sederhana yang diperiksa. Ini BUKAN jaminan aman. Verifikasi domain melalui kanal resmi."
        }
        return "INDIKATOR PERLU DIWASPADAI\\nHost: $host\\n\\n" +
            flags.joinToString(separator = "\\n") { "• $it" } +
            "\\n\\nJangan masukkan kata sandi, OTP, PIN, atau data pembayaran."
    }

    private fun showIncidentForm() {
        baseScreen("LAPORAN INSIDEN")
        paragraph("Catat informasi yang memang kamu miliki. Jangan mengarang identitas atau menyebarkan data pribadi.")
        label("Nama / alias terlapor")
        nameField = field("Nama atau alias")
        content.addView(nameField)
        label("Nomor / akun / rekening")
        contactField = field("Nomor telepon, username, atau rekening")
        content.addView(contactField)
        label("Platform")
        platformField = field("Contoh: WhatsApp, Instagram, marketplace")
        content.addView(platformField)
        label("Kronologi dan bukti")
        notesField = field("Tanggal, kejadian, nominal jika ada, dan bukti yang tersedia", true)
        content.addView(notesField)
        button("SIMPAN LAPORAN") {
            val name = nameField.text.toString().trim()
            val contact = contactField.text.toString().trim()
            val platform = platformField.text.toString().trim()
            val notes = notesField.text.toString().trim()
            if (contact.isBlank() || notes.isBlank()) {
                Toast.makeText(this, "Isi minimal kontak/akun dan kronologi.", Toast.LENGTH_LONG).show()
                return@button
            }
            val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
            val item = JSONObject().apply {
                put("time", stamp); put("name", name); put("contact", contact)
                put("platform", platform); put("notes", notes)
            }
            val all = loadItems()
            all.put(item)
            prefs.edit().putString("items", all.toString()).apply()
            Toast.makeText(this, "Laporan disimpan di perangkat.", Toast.LENGTH_LONG).show()
            showEvidence()
        }
        button("Kembali") { showHome() }
    }

    private fun loadItems(): JSONArray {
        return runCatching { JSONArray(prefs.getString("items", "[]")) }.getOrElse { JSONArray() }
    }

    private fun showEvidence() {
        baseScreen("BUKTI TERSIMPAN")
        val items = loadItems()
        if (items.length() == 0) paragraph("Belum ada laporan tersimpan.")
        for (i in 0 until items.length()) {
            val obj = items.optJSONObject(i) ?: continue
            val card = TextView(this).apply {
                text = "LAPORAN ${i + 1}\\nWaktu: ${obj.optString("time")}\\nNama/alias: ${obj.optString("name")}\\nKontak/akun: ${obj.optString("contact")}\\nPlatform: ${obj.optString("platform")}\\nKronologi: ${obj.optString("notes")}"
                textSize = 14f
                setTextColor(navy)
                setPadding(14, 14, 14, 14)
                background = android.graphics.drawable.GradientDrawable().apply {
                    setColor(Color.WHITE); cornerRadius = 14f
                    setStroke(1, Color.rgb(203, 213, 225))
                }
            }
            content.addView(card, LinearLayout.LayoutParams(-1, -2).apply { bottomMargin = 12 })
        }
        button("Bagikan semua laporan") { shareReport() }
        button("Hapus semua data lokal") {
            prefs.edit().remove("items").apply()
            Toast.makeText(this, "Data lokal dihapus.", Toast.LENGTH_SHORT).show()
            showEvidence()
        }
        button("Kembali") { showHome() }
    }

    private fun shareReport() {
        val items = loadItems()
        val out = StringBuilder("JACKCSALLAS ANTI-SCAM — RINGKASAN LAPORAN\\n")
        out.append("Dibuat: ").append(SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())).append("\\n")
        out.append("Jumlah insiden: ").append(items.length()).append("\\n\\n")
        for (i in 0 until items.length()) {
            val obj = items.optJSONObject(i) ?: continue
            out.append("LAPORAN ").append(i + 1).append("\\n")
            out.append("Waktu: ").append(obj.optString("time")).append("\\n")
            out.append("Nama/alias: ").append(obj.optString("name")).append("\\n")
            out.append("Kontak/akun: ").append(obj.optString("contact")).append("\\n")
            out.append("Platform: ").append(obj.optString("platform")).append("\\n")
            out.append("Kronologi: ").append(obj.optString("notes")).append("\\n\\n")
        }
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "Laporan insiden penipuan")
            putExtra(Intent.EXTRA_TEXT, out.toString())
        }
        startActivity(Intent.createChooser(intent, "Bagikan laporan"))
    }
}
