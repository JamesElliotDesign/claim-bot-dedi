const express = require("express");
const crypto = require("crypto");
const stringSimilarity = require("string-similarity");
const { sendServerMessage } = require("./services/cftoolsService");

require("dotenv").config();

const PORT = process.env.PORT || 8080;
const CF_WEBHOOK_SECRET = process.env.CF_WEBHOOK_SECRET;

const app = express();

// We need the raw request body for signature verification, so we use the 'verify' option.
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf; // Attach the raw body buffer to the request object
    }
}));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

const CLAIMS = {}; // Stores active POI claims
const CLAIM_TIMEOUT = 60 * 60 * 1000; // 60 minutes
const CLAIM_RADIUS = 500;

const { POI_POSITIONS } = require("./services/distanceCheck");
const { getAllOnlinePlayers } = require("./services/distanceCheck");

const MEMBER_EXPIRY = 60 * 60 * 1000; // 60 minutes
const INTRUSION_RADIUS = 200;
const INTRUSION_COOLDOWN = 5 * 60 * 1000; // 5 minutes
const lastIntrusionWarnings = {}; // { playerName: { poiName: timestamp } }

// 🟢 Command Regex
const CLAIM_REGEX = /^!?\/?claim\s+([A-Za-z0-9_ -]+)\b/i;
const CANCEL_CLAIM_REGEX = /^!?\/?cancel\s+([A-Za-z0-9_ -]+)\b/i;
const CHECK_CLAIMS_REGEX = /^!?\/?check claims\b/i;
const CHECK_POI_REGEX = /^!?\/?check\s+([A-Za-z0-9_ -]+)\b/i;

// 🛑 POIs that should NOT be listed in "Check Claims"
const EXCLUDED_POIS = [];

// 🛑 POIs that should BYPASS distance checks
const DYNAMIC_POIS = new Set([
    "Heli Crash (Event)",
    "Airdrop (Event)",
    "Knight (Quest)"
]);

// 🟢 POI LIST with Abbreviations
const POI_MAP = {
    "Biathlon Arena T5": "Biathlon Arena",
    "Sinystok Bunker T4": "Sinystok Bunker",
    "Yephbin Underground Facility T4": "Yephbin",
    "Rostoki Castle T5": "Rostoki",
    "Svetloyarsk Oil Rig T5": "Big Oil Rig",
    "Elektro Raider Outpost T1": "Elektro",
    "Otmel Raider Outpost T1": "Otmel",
    "Svetloyarsk Raider Outpost T1": "Svetloyarsk",
    "Solenchny Raider Outpost T1": "Solenchny",
    "Solnechny Oil Rig": "Small Oil Rig",
    "Klyuch Military T2": "Klyuch",
    "Rog Castle Military T2": "Rog",
    "Zub Castle Military T3": "Zub",
    "Kamensk Heli Depot T3": "Kamensk",
    "Metalurg Hydro Dam T3": "Metalurg",
    "Tisy Power Plant T4": "Tisy",
    "Krasno Warehouse T2": "Krasno",
    "Heli Crash (Event)": "Heli",
    "Airdrop (Event)": "Airdrop",
    "Knight (Quest)": "Knight",
    "Weed Farm (Event)": "Weed Farm",
    "Ghost Ship (Event)": "Ghost Ship",
    "Capital Bank (Event)": "Bank"
};

// 🛠 Common Abbreviations
const PARTIAL_POI_MAP = {
    "biathlon": "Biathlon Arena T5",
    "metalurg": "Metalurg Hydro Dam T3",
    "solenchny": "Solenchny Raider Outpost T1",
    "sol": "Solenchny Raider Outpost T1",
    "otmel": "Otmel Raider Outpost T1",
    "rostoki": "Rostoki Castle T5",
    "yephbin": "Yephbin Underground Facility T4",
    "krasno": "Krasno Warehouse T2",
    "svet": "Svetloyarsk Raider Outpost T1",
    "svetloyarsk": "Svetloyarsk Raider Outpost T1",
    "tisy": "Tisy Power Plant T4",
    "kamensk": "Kamensk Heli Depot T3",
    "elektro": "Elektro Raider Outpost T1",
    "klyuch": "Klyuch Military T2",
    "rog": "Rog Castle Military T2",
    "zub": "Zub Castle Military T3",
    "big oil rig": "Svetloyarsk Oil Rig T5",
    "small oil rig": "Solnechny Oil Rig",
    "big oil": "Svetloyarsk Oil Rig T5",
    "small oil": "Solnechny Oil Rig",
    "bunker": "Sinystok Bunker T4",
    "heli crash": "Heli Crash (Event)",
    "heli": "Heli Crash (Event)",
    "airdrop": "Airdrop (Event)",
    "knight": "Knight (Quest)",
    "farm": "Weed Farm (Event)",
    "weed": "Weed Farm (Event)",
    "ghost": "Ghost Ship (Event)",
    "ship": "Ghost Ship (Event)",
    "bank": "Capital Bank (Event)"
};

function scheduleClaimReset() {
    const now = new Date(Date.now() + 60 * 60 * 1000); // Simulate BST (GMT+1)
    const nextReset = new Date(now);

    const currentHour = now.getUTCHours();
    const currentMinute = now.getUTCMinutes();

    let nextBlock = Math.ceil((currentHour + currentMinute / 60) / 3) * 3;

    if (nextBlock >= 24) {
        nextReset.setUTCDate(nextReset.getUTCDate() + 1);
        nextReset.setUTCHours(0, 0, 0, 0);
    } else {
        nextReset.setUTCHours(nextBlock, 0, 0, 0);
    }

    const delay = nextReset.getTime() - now.getTime();

    console.log(`🕒 Now: ${new Date().toUTCString()}`);
    console.log(`⏳ Next POI reset scheduled in ${Math.floor(delay / 1000 / 60)} minutes at ${nextReset.toUTCString()}`);

    setTimeout(() => {
        resetClaims();
        setInterval(resetClaims, 3 * 60 * 60 * 1000);
    }, delay);
}

function resetClaims() {
    for (const poi in CLAIMS) {
        delete CLAIMS[poi];
    }
    console.log("♻️ Timed reset: All POI claims cleared due to server restart.");
    sendServerMessage("All POI claims have been reset after scheduled server restart.");
}

scheduleClaimReset();

/**
 * Validate webhook signature from CFTools
 */
// --- TEMPORARY DEBUGGING FUNCTION ---
function validateSignature(req) {
    console.log("--- Starting Signature Validation ---");

    const receivedSignature = req.headers["x-cf-signature"];
    if (!receivedSignature) {
        console.error("Validation failed: No 'x-cf-signature' header found on the request.");
        return false;
    }
    
    if (!CF_WEBHOOK_SECRET || CF_WEBHOOK_SECRET.length === 0) {
        console.error("Validation failed: The CF_WEBHOOK_SECRET environment variable is not set or is empty!");
        return false;
    }

    // This buffer is what the signature is based on. Let's log its size.
    console.log(`Raw Body Size: ${req.rawBody.length} bytes`);

    // Log the signature we received from the header
    console.log(`Received Signature from CFTools: ${receivedSignature}`);

    // Generate our local signature using the exact same method
    const localSignature = crypto
        .createHmac("sha256", CF_WEBHOOK_SECRET)
        .update(req.rawBody)
        .digest("hex");

    // Log the signature we just created
    console.log(`Locally Generated Signature:    ${localSignature}`);

    // Perform the comparison
    const signaturesMatch = crypto.timingSafeEqual(
        Buffer.from(receivedSignature), 
        Buffer.from(localSignature)
    );

    console.log(`Do signatures match? ${signaturesMatch}`);
    console.log("--- Finished Signature Validation ---");

    return signaturesMatch;
}

/**
 * Finds the closest matching POI
 */
function findMatchingPOI(input) {
    let normalizedPOI = input.trim().toLowerCase().replace(/\s+/g, " ");
    let correctedPOI = PARTIAL_POI_MAP[normalizedPOI] || POI_MAP[normalizedPOI];
    if (!correctedPOI) {
        let bestMatch = stringSimilarity.findBestMatch(
            normalizedPOI,
            [...Object.keys(POI_MAP), ...Object.values(POI_MAP), ...Object.keys(PARTIAL_POI_MAP)]
        );
        if (bestMatch.bestMatch.rating >= 0.6) {
            correctedPOI = PARTIAL_POI_MAP[bestMatch.bestMatch.target] || POI_MAP[bestMatch.bestMatch.target] || bestMatch.bestMatch.target;
        }
    }
    return correctedPOI || null;
}

function getDistance(posA, posB) {
    const dx = posA.x - posB.x;
    const dy = posA.y - posB.y;
    const dz = posA.z - posB.z;
    return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

async function pollPlayerIntrusions() {
    try {
        const players = await getAllOnlinePlayers();
        if (!players || players.length === 0) return;
        for (const player of players) {
            const name = player.name;
            const pos = player.position; // [X, Z, Y]
            if (Array.isArray(pos)) {
                await checkPOIIntrusion(name, pos);
            }
        }
    } catch (err) {
        console.error("❌ Error polling player intrusions:", err.message);
    }
}

async function checkPOIIntrusion(playerName, playerPosition) {
    const now = Date.now();
    for (let poiName in POI_POSITIONS) {
        const poiPos = POI_POSITIONS[poiName];
        const normalizedPlayer = playerName.trim().toLowerCase();
        const claim = CLAIMS[poiName];
        if (
            claim &&
            (
                claim.player === normalizedPlayer ||
                (claim.members || []).some(m =>
                    m.name === normalizedPlayer && now - m.timestamp < MEMBER_EXPIRY
                )
            )
        ) continue;

        if (EXCLUDED_POIS.includes(poiName)) continue;

        const distance = getDistance(
            { x: playerPosition[0], y: 0, z: playerPosition[1] },
            { x: poiPos[0], y: 0, z: poiPos[2] }
        );
        console.log(`📍 ${playerName} distance to ${poiName}: ${distance.toFixed(2)}m`);

        if (distance <= INTRUSION_RADIUS) {
            if (!lastIntrusionWarnings[playerName]) {
                lastIntrusionWarnings[playerName] = {};
            }
            const lastWarned = lastIntrusionWarnings[playerName][poiName] || 0;
            if (now - lastWarned >= INTRUSION_COOLDOWN) {
                lastIntrusionWarnings[playerName][poiName] = now;
                await sendServerMessage(`Warning: ${playerName} entered ${poiName} without claiming it!`);
            }
        }
    }
}

function cleanExpiredGroupMembers() {
    const now = Date.now();
    for (const poi in CLAIMS) {
        if (!CLAIMS[poi].members) continue;
        CLAIMS[poi].members = CLAIMS[poi].members.filter(member => {
            return now - member.timestamp < MEMBER_EXPIRY;
        });
    }
}

setInterval(cleanExpiredGroupMembers, 60 * 1000);

function releaseExpiredPOIs() {
    const now = Date.now();
    for (let poi in CLAIMS) {
        if (now - CLAIMS[poi].timestamp >= CLAIM_TIMEOUT) {
            delete CLAIMS[poi];
            sendServerMessage(`The claim on ${poi} has expired and is now available.`);
        }
    }
}

setInterval(releaseExpiredPOIs, 60 * 1000);

const processedMessages = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key, timestamp] of processedMessages.entries()) {
        if (now - timestamp > 10000) {
            processedMessages.delete(key);
        }
    }
}, 5000);


/**
 * Webhook handler
 */
app.post("/webhook", async (req, res) => {
    // 1. Validate the signature FIRST
    if (!validateSignature(req)) {
        console.error("❌ Webhook Error: Invalid signature.");
        return res.status(403).send("Forbidden");
    }

    try {
        // 2. Check for the correct event header and type
        const eventType = req.headers["x-cf-event"];
        if (eventType !== "CHAT") {
            return res.status(200).send("Event received, but not processed.");
        }

        // 3. Destructure the payload correctly
        const { payload } = req.body;
        if (!payload || !payload.player_name || !payload.message) {
            console.error("❌ Webhook Error: Malformed chat payload.");
            return res.status(400).send("Bad Request: Malformed Payload");
        }
        
        const { message, player_name } = payload;
        const messageContent = message.toLowerCase();
        const playerName = player_name;

        console.log(`[Game Chat] ${playerName}: ${messageContent}`);

        // Prevent duplicate processing
        const messageKey = `${playerName}-${messageContent}`;
        if (processedMessages.has(messageKey)) {
            console.log(`🛑 Duplicate message detected, ignoring: ${messageKey}`);
            return res.sendStatus(204);
        }
        processedMessages.set(messageKey, Date.now());

        // "Check Claims"
        if (CHECK_CLAIMS_REGEX.test(messageContent)) {
            let availablePOIs = Object.keys(POI_MAP).filter(poi => !CLAIMS[poi] && !EXCLUDED_POIS.includes(poi));
            if (availablePOIs.length === 0) {
                await sendServerMessage("All POIs are currently claimed.");
            } else {
                await sendServerMessage(`Available POIs: ${availablePOIs.map(poi => POI_MAP[poi]).join(", ")}`);
            }
            return res.sendStatus(204);
        }

        // "Check POI"
        const checkMatch = messageContent.match(CHECK_POI_REGEX);
        if (checkMatch) {
            let correctedPOI = findMatchingPOI(checkMatch[1]);
            if (!correctedPOI) {
                await sendServerMessage(`Unknown POI: ${checkMatch[1]}. Try 'check claims' to see available POIs.`);
                return res.sendStatus(204);
            }
            await sendServerMessage(
                CLAIMS[correctedPOI] 
                    ? `${correctedPOI} is claimed by ${CLAIMS[correctedPOI].displayName}.` 
                    : `${correctedPOI} is available to claim!`
            );
            return res.sendStatus(204);
        }

        // "Claim POI"
        const claimMatch = messageContent.match(CLAIM_REGEX);
        if (claimMatch) {
            let correctedPOI = findMatchingPOI(claimMatch[1]);
            if (!correctedPOI) {
                await sendServerMessage(`Invalid POI: ${claimMatch[1]}. Try 'check claims' to see available POIs.`);
                return res.sendStatus(204);
            }
            if (CLAIMS[correctedPOI]) {
                let timeSinceClaim = Math.floor((Date.now() - CLAIMS[correctedPOI].timestamp) / 60000);
                await sendServerMessage(`${correctedPOI} was already claimed by ${CLAIMS[correctedPOI].displayName} ${timeSinceClaim} minutes ago.`);
                return res.sendStatus(204);
            }
            if (!DYNAMIC_POIS.has(correctedPOI)) {
                const { isPlayerNearPOI } = require("./services/distanceCheck");
                const checkResult = await isPlayerNearPOI(playerName, correctedPOI);
                if (!checkResult.success) {
                    await sendServerMessage(checkResult.message);
                    return res.sendStatus(204);
                }
            } else {
                console.log(`🛑 Distance check bypassed for dynamic POI: ${correctedPOI}`);
            }
            const normalizedClaimant = playerName.trim().toLowerCase();
            CLAIMS[correctedPOI] = {
                player: normalizedClaimant,
                displayName: playerName.trim(),
                timestamp: Date.now(),
                members: [{ name: normalizedClaimant, timestamp: Date.now() }]
            };
            
            const allPlayers = await getAllOnlinePlayers();
            for (const p of allPlayers) {
                const normalized = p.name.trim().toLowerCase();
                const dist = getDistance(
                    { x: p.position[0], y: 0, z: p.position[1] },
                    { x: POI_POSITIONS[correctedPOI][0], y: 0, z: POI_POSITIONS[correctedPOI][2] }
                );
                if (dist <= CLAIM_RADIUS) {
                    const alreadyAdded = CLAIMS[correctedPOI].members.some(m => m.name === normalized);
                    if (!alreadyAdded) {
                        CLAIMS[correctedPOI].members.push({
                            name: normalized,
                            displayName: p.name.trim(),
                            timestamp: Date.now()
                        });
                        console.log(`👥 ${p.name} added to ${correctedPOI} group (${dist.toFixed(2)}m)`);
                    }
                }
            }

            const groupNames = CLAIMS[correctedPOI].members.map(m => m.name);
            console.log(`🧩 ${playerName} claimed ${correctedPOI} with group: [${groupNames.join(', ')}]`);

            const displayNames = CLAIMS[correctedPOI].members
                .filter(m => m.name !== normalizedClaimant)
                .map(m => m.displayName || m.name);
            let groupMsg = "";
            if (displayNames.length > 0) {
                groupMsg = ` with ${displayNames.join(", ")}`;
            }
            await sendServerMessage(`${playerName} successfully claimed ${correctedPOI}${groupMsg}.`);
            return res.sendStatus(204);
        }

        // "Unclaim POI"
        const unclaimMatch = messageContent.match(CANCEL_CLAIM_REGEX);
        if (unclaimMatch) {
            let correctedPOI = findMatchingPOI(unclaimMatch[1]);
            if (!correctedPOI || !CLAIMS[correctedPOI]) {
                await sendServerMessage(correctedPOI 
                    ? `${correctedPOI} is not currently claimed.` 
                    : `Invalid POI: ${unclaimMatch[1]}. Try 'check claims' to see available POIs.`
                );
                return res.sendStatus(204);
            }
            const normalizedPlayer = playerName.trim().toLowerCase();
            if (CLAIMS[correctedPOI].player !== normalizedPlayer) {
                await sendServerMessage(`You cannot cancel claim on ${correctedPOI}. It was claimed by ${CLAIMS[correctedPOI].displayName}.`);
                return res.sendStatus(204);
            }
            delete CLAIMS[correctedPOI];
            await sendServerMessage(`${playerName} cancelled their claim on ${correctedPOI}.`);
            return res.sendStatus(204);
        }

        res.sendStatus(204);
    } catch (err) {
        console.error("❌ Webhook Error:", err);
        res.sendStatus(500);
    }
});

setInterval(pollPlayerIntrusions, 120 * 1000);
app.listen(PORT, () => console.log(`🚀 Webhook Server listening on port ${PORT}`));