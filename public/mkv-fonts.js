/**
 * MKV Font Extractor for HaruStream
 * Extracts font attachments (TTF/OTF/WOFF) from an MKV file over HTTP using Range requests.
 */

window.MkvFontExtractor = class MkvFontExtractor {
    constructor(url, headers = {}) {
        this.url = url;
        this.headers = headers;
        this.segmentOffset = 0;
    }

    async extractFonts() {
        console.log("[MKV Font Extractor] Starting extraction...");
        try {
            // First try: 1MB chunk, then try up to 10MB chunk if fonts are large
            const resp = await this.fetchRange(0, 1024 * 1024 * 5); // 5MB to be safe for large fonts
            const data = new Uint8Array(await resp.arrayBuffer());
            
            let extractedSubContent = null;
            // Try to extract CodecPrivate (ASS Styles)
            const tracksIdx = this.indexOfSequence(data, [0x16, 0x54, 0xAE, 0x6B]);
            if (tracksIdx !== -1) {
                let offset = tracksIdx + 4;
                const sizeVint = this.readVint(data, offset);
                if (sizeVint) {
                    offset += sizeVint.length;
                    const end = offset + sizeVint.value;
                    let pIdIdx = this.indexOfSequence(data, [0x63, 0xA2], tracksIdx);
                    while (pIdIdx !== -1 && pIdIdx < end) {
                        let pSizeVint = this.readVint(data, pIdIdx + 2);
                        if (pSizeVint) {
                            let pData = new TextDecoder().decode(data.slice(pIdIdx + 2 + pSizeVint.length, pIdIdx + 2 + pSizeVint.length + pSizeVint.value));
                            if (pData.includes('[V4+ Styles]')) {
                                extractedSubContent = pData;
                                console.log("[MKV Font Extractor] Successfully extracted ASS CodecPrivate (Styles)");
                                break;
                            }
                        }
                        pIdIdx = this.indexOfSequence(data, [0x63, 0xA2], pIdIdx + 2);
                    }
                }
            }

            const segmentIdx = this.indexOfSequence(data, [0x18, 0x53, 0x80, 0x67]);
            if (segmentIdx === -1) {
                console.warn("[MKV Font Extractor] Segment not found in first chunk.");
                return { fonts: [], subContent: extractedSubContent };
            }
            
            let offset = segmentIdx + 4;
            const sizeVint = this.readVint(data, offset);
            if (sizeVint) offset += sizeVint.length;
            this.segmentOffset = offset;
            console.log("[MKV Font Extractor] Segment payload starts at", this.segmentOffset);

            let allFonts = [];
            let currentOffset = offset;
            
            while (currentOffset < data.length) {
                let attachmentsIdx = this.indexOfSequence(data, [0x19, 0x41, 0xA4, 0x69], currentOffset);
                if (attachmentsIdx === -1) break;
                
                console.log("[MKV Font Extractor] Found Attachments block at offset", attachmentsIdx);
                const blockFonts = this.parseAttachments(data, attachmentsIdx);
                if (blockFonts.length > 0) {
                    allFonts = allFonts.concat(blockFonts);
                }
                
                // Move currentOffset past the ID
                const attSizeVint = this.readVint(data, attachmentsIdx + 4);
                if (attSizeVint) {
                    currentOffset = attachmentsIdx + 4 + attSizeVint.length + attSizeVint.value;
                } else {
                    currentOffset = attachmentsIdx + 4;
                }
            }

            if (allFonts.length > 0) {
                console.log("[MKV Font Extractor] Successfully accumulated fonts directly!");
                return { fonts: allFonts, subContent: extractedSubContent };
            }
            
            console.log("[MKV Font Extractor] Attachments not found directly, looking for SeekHead...");
            const seekHeadIdx = this.indexOfSequence(data, [0x11, 0x4D, 0x9B, 0x74], offset);
            if (seekHeadIdx !== -1) {
                const attachmentsOffset = this.parseSeekHead(data, seekHeadIdx);
                if (attachmentsOffset !== -1) {
                    const absOffset = this.segmentOffset + attachmentsOffset;
                    console.log("[MKV Font Extractor] Found Attachments via SeekHead at absolute offset", absOffset);
                    const attResp = await this.fetchRange(absOffset, absOffset + 5 * 1024 * 1024);
                    const attData = new Uint8Array(await attResp.arrayBuffer());
                    let attIdx = this.indexOfSequence(attData, [0x19, 0x41, 0xA4, 0x69]);
                    if (attIdx !== -1) {
                        return { fonts: this.parseAttachments(attData, attIdx), subContent: extractedSubContent };
                    }
                }
            }
            
            console.log("[MKV Font Extractor] No fonts found.");
            return { fonts: [], subContent: extractedSubContent };
        } catch (err) {
            console.error("[MKV Font Extractor] Error:", err);
            return { fonts: [], subContent: null };
        }
    }

    parseSeekHead(data, offset) {
        offset += 4;
        const sizeVint = this.readVint(data, offset);
        if (!sizeVint) return -1;
        offset += sizeVint.length;
        const end = offset + sizeVint.value;

        while (offset < end && offset < data.length) {
            const seekIdx = this.indexOfSequence(data, [0x4D, 0xBB], offset);
            if (seekIdx === -1 || seekIdx >= end) break;
            
            offset = seekIdx + 2;
            const seekSizeVint = this.readVint(data, offset);
            if (!seekSizeVint) break;
            offset += seekSizeVint.length;
            const seekEnd = offset + seekSizeVint.value;

            let seekId = null;
            let seekPos = -1;

            while (offset < seekEnd) {
                if (data[offset] === 0x53 && data[offset+1] === 0xAB) {
                    offset += 2;
                    const idSize = this.readVint(data, offset);
                    offset += idSize.length;
                    seekId = data.slice(offset, offset + idSize.value);
                    offset += idSize.value;
                } else if (data[offset] === 0x53 && data[offset+1] === 0xAC) {
                    offset += 2;
                    const posSize = this.readVint(data, offset);
                    offset += posSize.length;
                    seekPos = this.readUint(data, offset, posSize.value);
                    offset += posSize.value;
                } else {
                    const elIdSize = this.getVintLength(data[offset]);
                    const elSize = this.readVint(data, offset + elIdSize);
                    offset += elIdSize + elSize.length + elSize.value;
                }
            }

            if (seekId && seekId.length === 4 && 
                seekId[0] === 0x19 && seekId[1] === 0x41 && seekId[2] === 0xA4 && seekId[3] === 0x69) {
                return seekPos;
            }
        }
        return -1;
    }

    parseAttachments(data, offset) {
        const fonts = [];
        offset += 4;
        const sizeVint = this.readVint(data, offset);
        if (!sizeVint) return fonts;
        offset += sizeVint.length;
        const end = offset + sizeVint.value;

        while (offset < end && offset < data.length) {
            const fileIdx = this.indexOfSequence(data, [0x61, 0xA7], offset);
            if (fileIdx === -1 || fileIdx >= end) break;
            
            offset = fileIdx + 2;
            const fileSizeVint = this.readVint(data, offset);
            if (!fileSizeVint) break;
            offset += fileSizeVint.length;
            const fileEnd = offset + fileSizeVint.value;

            let fileName = "";
            let mimeType = "";
            let fileData = null;

            while (offset < fileEnd) {
                if (data[offset] === 0x46 && data[offset+1] === 0x6E) {
                    offset += 2;
                    const elSize = this.readVint(data, offset);
                    offset += elSize.length;
                    fileName = new TextDecoder("utf-8").decode(data.slice(offset, offset + elSize.value)).replace(/\0/g, "");
                    offset += elSize.value;
                } else if (data[offset] === 0x46 && data[offset+1] === 0x60) {
                    offset += 2;
                    const elSize = this.readVint(data, offset);
                    offset += elSize.length;
                    mimeType = new TextDecoder("ascii").decode(data.slice(offset, offset + elSize.value)).replace(/\0/g, "");
                    offset += elSize.value;
                } else if (data[offset] === 0x46 && data[offset+1] === 0x5C) {
                    offset += 2;
                    const elSize = this.readVint(data, offset);
                    offset += elSize.length;
                    fileData = data.slice(offset, offset + elSize.value);
                    offset += elSize.value;
                } else {
                    const idLen = this.getVintLength(data[offset]);
                    const elSize = this.readVint(data, offset + idLen);
                    if (!elSize) break;
                    offset += idLen + elSize.length + elSize.value;
                }
            }

            if (mimeType.includes("font") || mimeType.includes("truetype") || mimeType.includes("opentype") || mimeType.includes("application/x-truetype-font") || fileName.endsWith(".ttf") || fileName.endsWith(".otf") || fileName.endsWith(".woff")) {
                console.log("[MKV Font Extractor] Found font:", fileName);
                if (fileData) {
                    fonts.push(new Uint8Array(fileData));
                }
            }
        }
        return fonts;
    }

    async fetchRange(start, end) {
        const h = { ...this.headers, "Range": `bytes=${start}-${end}` };
        const res = await fetch(this.url, { headers: h });
        if (!res.ok && res.status !== 206) throw new Error("HTTP error " + res.status);
        return res;
    }

    getVintLength(firstByte) {
        let length = 1;
        let mask = 0x80;
        while ((firstByte & mask) === 0 && length < 8) {
            mask >>= 1;
            length++;
        }
        return length;
    }

    readVint(data, offset) {
        if (offset >= data.length) return null;
        const length = this.getVintLength(data[offset]);
        if (offset + length > data.length) return null;
        let value = data[offset] & ~(0x80 >> (length - 1));
        for (let i = 1; i < length; i++) {
            value = (value * 256) + data[offset + i];
        }
        return { value, length };
    }

    readUint(data, offset, length) {
        let val = 0;
        for (let i = 0; i < length; i++) {
            val = (val * 256) + data[offset + i];
        }
        return val;
    }

    indexOfSequence(data, seq, startOffset = 0) {
        for (let i = startOffset; i <= data.length - seq.length; i++) {
            let match = true;
            for (let j = 0; j < seq.length; j++) {
                if (data[i + j] !== seq[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }
};
