/*
 * Example of ML-DSA-44 (FIPS 204) running on an ESP32 Lilygo T-Display-S3.
 * It uses the TFT_eSPI library to show a modern, real-time UI process.
 * 
 * IMPORTANT: ML-DSA-44 requires ~32KB of working memory to sign a message. 
 * Because the default loop() task stack in Arduino is too small (usually 8KB), 
 * we MUST run the cryptography in a dedicated FreeRTOS task with 64KB stack!
 */

#include <Arduino.h>
#include <TFT_eSPI.h> 
#include <MLDSA44.h>

TFT_eSPI tft = TFT_eSPI();

// Custom Colors
#define NEURAI_PURPLE 0x91BA // RGB565 for (147, 49, 212)
#define DARK_GRAY     0x10A2
#define CARD_BG       0x2124
#define STATUS_OK     0x07E0 // Green
#define STATUS_ERR    0xF800 // Red

void drawHeader() {
  tft.fillRect(0, 0, 320, 26, NEURAI_PURPLE); // Top Bar made slightly thinner
  tft.setTextColor(TFT_WHITE, NEURAI_PURPLE); // White text looks better on purple
  tft.setTextDatum(MC_DATUM);                 // Middle Center
  // Font 4 is a nice, smooth 26-pixel high font
  tft.drawString("Neurai ML-DSA-44", 160, 14, 4);
}

void drawCard(int y, const char* title) {
  tft.fillRoundRect(10, y, 300, 40, 5, CARD_BG);
  tft.setTextColor(TFT_LIGHTGREY, CARD_BG);
  tft.setTextDatum(ML_DATUM);               // Middle Left
  tft.drawString(title, 20, y + 20, 2);     // Font 2 is a smooth 16-pixel font
}

void updateStatus(int y, const char* status, uint16_t color, uint32_t ms) {
  char buf[32];
  if(ms > 0) {
    sprintf(buf, "%s (%lu ms)", status, ms);
  } else {
    sprintf(buf, "%s", status);
  }
  
  tft.setTextColor(color, CARD_BG);
  tft.setTextDatum(MR_DATUM);               // Middle Right
  // Draw over previous status by filling a small rect, then string
  tft.fillRect(150, y + 5, 150, 30, CARD_BG); 
  tft.drawString(buf, 300, y + 20, 2);
}

void cryptoTask(void *pvParameters) {
  uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
  uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
  uint8_t sig[MLDSA44::SIGNATURE_SIZE];
  size_t siglen;

  const char *msg = "Neurai Security Token";

  // Step 1: Keygen
  // Y = 32 (right below 26px header + 6px gap)
  drawCard(32, "Keypair Gen:");
  updateStatus(32, "Working...", TFT_YELLOW, 0);
  
  uint32_t t_start = millis();
  int res = MLDSA44::generateKeypair(pk, sk);
  uint32_t t_end = millis();

  if (res != 0) {
    updateStatus(32, "FAILED", STATUS_ERR, 0);
    vTaskDelete(NULL);
    return;
  }
  updateStatus(32, "READY", STATUS_OK, t_end - t_start);
  delay(300); // Small pause for UX

  // Step 2: Signing
  // Y = 74 (32 + 40 height + 2 gap)
  drawCard(76, "Signature:");
  updateStatus(76, "Signing...", TFT_YELLOW, 0);

  t_start = millis();
  res = MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk);
  t_end = millis();

  if (res != 0) {
    updateStatus(76, "FAILED", STATUS_ERR, 0);
    vTaskDelete(NULL);
    return;
  }
  updateStatus(76, "SIGNED", STATUS_OK, t_end - t_start);
  
  // Show signature size info packed closer
  tft.setTextColor(TFT_DARKGREY, TFT_BLACK);
  tft.setTextDatum(ML_DATUM);
  tft.drawString("Size: 2420 Bytes gen.", 15, 120, 1); // Font 1 (small) to save space
  delay(500);

  // Step 3: Verification
  // Y = 126 (leaves space for the small text above, fits inside 170px limit)
  drawCard(128, "Verification:");
  updateStatus(128, "Checking...", TFT_YELLOW, 0);

  t_start = millis();
  res = MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk);
  t_end = millis();

  if (res == 0) {
    updateStatus(128, "SUCCESS", STATUS_OK, t_end - t_start);
  } else {
    updateStatus(128, "FAILED", STATUS_ERR, 0);
  }

  // Good security practice: clean up secret key from RAM
  memset(sk, 0, sizeof(sk));
  
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);

  // Initialize Screen
  tft.init();
  tft.setRotation(1); // Landscape mode typical for T-Display (320x170)
  tft.fillScreen(TFT_BLACK);
  
  drawHeader();

  // Create Crypto Task (64KB stack)
  xTaskCreate(cryptoTask, "crypto", 65536, NULL, 1, NULL);
}

void loop() {
  delay(1000);
}
