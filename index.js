const express = require("express");
require("dotenv").config();

const PORT = process.env.PORT || 8080;
const app = express();

// Middleware to parse JSON. We don't need the raw body for this test.
app.use(express.json());

// The ONLY route. Its job is to log everything about the request.
app.post("/webhook", (req, res) => {
    console.log("--- DIAGNOSTIC LOG: A WEBHOOK WAS RECEIVED ---");

    try {
        // Log all headers as a single JSON object for easy reading
        console.log("HEADERS RECEIVED:", JSON.stringify(req.headers, null, 2));

        // Log the parsed JSON body to see the payload
        console.log("BODY RECEIVED:", JSON.stringify(req.body, null, 2));

    } catch (e) {
        console.error("Error during logging:", e);
    }

    console.log("--- END OF DIAGNOSTIC LOG ---");

    // Respond with 200 OK to let CFTools know we received it without error.
    res.status(200).send("OK");
});

app.listen(PORT, () => console.log(`🚀 Diagnostic Server listening on port ${PORT}`));