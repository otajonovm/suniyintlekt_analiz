import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Initialize Gemini API securely server-side
  const geminiApiKey = process.env.GEMINI_API_KEY;
  let ai: GoogleGenAI | null = null;

  if (geminiApiKey) {
    ai = new GoogleGenAI({
      apiKey: geminiApiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
    console.log("Gemini API Client initialized successfully.");
  } else {
    console.warn("GEMINI_API_KEY environment variable is not defined.");
  }

  // API endpoint for chatbot
  app.post("/api/gemini/chat", async (req, res) => {
    try {
      if (!ai) {
        return res.status(500).json({
          error: "Gemini API is not configured. Please check your secrets in the Settings menu.",
        });
      }

      const { message, history } = req.body;

      if (!message) {
        return res.status(400).json({ error: "Message is required" });
      }

      // Convert history to Gemini format if provided, otherwise start fresh
      // Prepare a strict system instruction explaining Artificial Immune Systems (AIS)
      // and analyzing malware/threats.
      const systemInstruction = `Siz "NetImmune AIS" (Sun'iy Immun Tizimi Tarmoq Himoyasi) platformasining intellektual tahlilchisi va xavfsizlik botisiz.
Foydalanuvchilarga tarmoqdagi zararkunanda dasturlar (malware) va anomaliyalarni Sun'iy Immun Tizimlari (Artificial Immune Systems - AIS) yordamida aniqlash bo'yicha tushunchalar berasiz.
Sizning bilimlaringiz quyidagi asosiy sohalarni qamrab oladi:
1. Salbiy Tanlash Algoritmi (Negative Selection Algorithm - NSA): T-hujayralarining "self" (sog'lom) va "non-self" (begona/zararkunanda) profilini yaratish, detektorlarni hosil qilish va ularning sog'lom hujayralar bilan reaksiyaga kirishishini (autoimmun) tekshirib, yaroqsizlarini o'chirish.
2. Klon Tanlash Algoritmi (Clonal Selection Algorithm - CSA): B-hujayralarining antigenlar (zararkunandalar) bilan bog'lanishi, eng yuqori afillikka (o'xshashlikka) ega bo'lganlarini klonlash, mutatsiya qilish va xotira hujayralari (memory cells) sifatida saqlab qolish.
3. Dendrit Hujayralar Algoritmi (Dendritic Cell Algorithm - DCA): PAMP (Pathogen-Associated Molecular Patterns - zararkunanda belgilari), Danger Signals (DS - xavf signallari, masalan CPU qizishi yoki tarmoq bandligi) va Safe Signals (SS - xavfsiz signallar) tahlili orqali anomal holatlarni aniqlash.

Foydalanuvchi tarmoq loglarini (log traces) jo'natishi mumkin. Siz ularni AIS nuqtai nazaridan tahlil qiling:
- Antigenlarni ajratib oling (IP, port, paket hajmi, baytlar ketma-ketligi)
- Ularni "self" (xavfsiz) yoki "non-self" (zararli) ekanligini baholang
- Tizim uchun immun qoidasi yoki detektor tavsiya qiling.

Siz har doim savollarga o'zbek tilida (yoki foydalanuvchi so'ragan tilda) aniq, professional, tushunarli va ilmiy tilda javob berishingiz kerak.
Javoblaringizda dizayn yoki dastur fayllariga emas, balki tarmoq xavfsizligi va biologik immun tizimlari qiyosiga e'tibor qarating.`;

      // Structure contents with history for full context
      const contents: any[] = [];
      
      if (history && Array.isArray(history)) {
        history.forEach((chatMsg: any) => {
          contents.push({
            role: chatMsg.role === "user" ? "user" : "model",
            parts: [{ text: chatMsg.text }],
          });
        });
      }

      contents.push({
        role: "user",
        parts: [{ text: message }],
      });

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents,
        config: {
          systemInstruction,
          temperature: 0.7,
        },
      });

      res.json({ text: response.text });
    } catch (error: any) {
      console.error("Gemini API Error:", error);
      res.status(500).json({ error: error.message || "Xatolik yuz berdi" });
    }
  });

  // Serve static files in production, use Vite middleware in dev
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    // SPA fallback
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Express server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
});
