const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { chromium } = require('C:/Users/nixon/CloudBill/node_modules/playwright-core');
const ffmpeg = require('C:/Users/nixon/CloudBill/node_modules/ffmpeg-static');

async function main() {
  console.log('=== AI-VAPT AGENT Automated Demo Video Generator ===');
  
  const baseDir = __dirname;
  const audioDir = path.join(baseDir, 'recordings', 'audio_segments');
  const recordingsDir = path.join(baseDir, 'recordings');
  const tempVideoDir = path.join(recordingsDir, 'temp_video_raw');

  // Read segment durations
  const durationsPath = path.join(audioDir, 'durations.json');
  if (!fs.existsSync(durationsPath)) {
    throw new Error('durations.json not found! Run generate_audio.py first.');
  }
  const durations = JSON.parse(fs.readFileSync(durationsPath, 'utf8'));
  console.log('Audio Segment Durations (seconds):', durations);

  const segmentKeys = [
    '01_intro',
    '02_dashboard',
    '03_targets',
    '04_ai_agent',
    '05_scanners',
    '06_findings',
    '07_approvals',
    '08_reports',
    '09_closing'
  ];

  // 1. Create master concatenated audio file (if not exists)
  const masterAudio = path.join(recordingsDir, 'voiceover_master.wav');
  if (!fs.existsSync(masterAudio)) {
    console.log('\n1. Creating master concatenated audio track...');
    const concatList = segmentKeys.map(k => `file '${path.join(audioDir, `${k}.wav`).replace(/\\/g, '/')}'`).join('\n');
    fs.writeFileSync(path.join(audioDir, 'concat.txt'), concatList);
    execSync(`"${ffmpeg}" -f concat -safe 0 -i "${path.join(audioDir, 'concat.txt')}" -c copy "${masterAudio}"`);
  }
  console.log('   Master audio ready:', masterAudio);

  // 2. Setup Playwright recording
  console.log('\n2. Setting up Playwright Chromium screen recording...');
  if (fs.existsSync(tempVideoDir)) fs.rmSync(tempVideoDir, { recursive: true, force: true });
  fs.mkdirSync(tempVideoDir, { recursive: true });

  const browser = await chromium.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: true,
  });

  const context = await browser.newContext({
    recordVideo: {
      dir: tempVideoDir,
      size: { width: 1366, height: 768 },
    },
    viewport: { width: 1366, height: 768 },
  });

  const page = await context.newPage();
  const wait = (ms) => page.waitForTimeout(ms);

  // Helper for safe page navigation
  const safeGoto = async (url) => {
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await wait(1000);
    } catch (e) {
      console.log(`   Nav warning for ${url}:`, e.message);
    }
  };

  // ── SEGMENT 1: Intro (Dashboard) ───────────────────────────────────
  console.log('\n🎬 Segment 1: Intro & Platform Overview');
  const seg1Dur = (durations['01_intro'] || 37) * 1000;
  await safeGoto('http://localhost:5173/');
  await wait(4000);
  await page.evaluate(() => window.scrollBy({ top: 200, behavior: 'smooth' }));
  await wait(3000);
  await page.evaluate(() => window.scrollBy({ top: -200, behavior: 'smooth' }));
  await wait(Math.max(2000, seg1Dur - 10000));

  // ── SEGMENT 2: Dashboard Deep Dive ────────────────────────────────
  console.log('🎬 Segment 2: SOC Dashboard & Severity Analytics');
  const seg2Dur = (durations['02_dashboard'] || 35) * 1000;
  await wait(2000);
  await page.evaluate(() => window.scrollBy({ top: 400, behavior: 'smooth' }));
  await wait(4000);
  await page.evaluate(() => window.scrollBy({ top: 450, behavior: 'smooth' }));
  await wait(4000);
  await page.evaluate(() => window.scrollBy({ top: -850, behavior: 'smooth' }));
  await wait(Math.max(2000, seg2Dur - 11000));

  // ── SEGMENT 3: Target Management & Scope Enforcement ───────────────
  console.log('🎬 Segment 3: Target Scope & Audit Log');
  const seg3Dur = (durations['03_targets'] || 55) * 1000;
  await safeGoto('http://localhost:5173/targets');
  await wait(3000);

  // Click Register Target button to show modal
  try {
    const regBtn = await page.$('button:has-text("Register Target")');
    if (regBtn) {
      await regBtn.click();
      await wait(3000);
      const hostInput = await page.$('input[placeholder*="192.168"], input[name="host"]');
      if (hostInput) await hostInput.fill('192.168.1.50');
      await wait(2000);
      const cancelBtn = await page.$('button:has-text("Cancel")');
      if (cancelBtn) await cancelBtn.click();
      await wait(1500);
    }
  } catch (e) {
    console.log('   Modal interaction skipped:', e.message);
  }

  // Scroll down to Scope Audit Log with validated timestamps
  await page.evaluate(() => window.scrollBy({ top: 450, behavior: 'smooth' }));
  await wait(6000);
  await page.evaluate(() => window.scrollBy({ top: -450, behavior: 'smooth' }));
  await wait(Math.max(2000, seg3Dur - 16500));

  // ── SEGMENT 4: Conversational AI Agent & Target Mismatch Guard ─────
  console.log('🎬 Segment 4: Conversational AI Planner & Target Mismatch Detection');
  const seg4Dur = (durations['04_ai_agent'] || 84) * 1000;
  await safeGoto('http://localhost:5173/agent');
  await wait(3000);

  // Send first legitimate prompt
  try {
    const chatInput = await page.$('textarea, input[placeholder*="Ask"], input[placeholder*="security"]');
    if (chatInput) {
      await chatInput.fill('Perform a web vulnerability assessment on 192.168.1.50.');
      await wait(1500);
      const sendBtn = await page.$('button[type="submit"], button:has-text("Send")');
      if (sendBtn) await sendBtn.click();
      await wait(7000);

      // Scroll chat to view 6-stage plan
      await page.evaluate(() => window.scrollBy({ top: 350, behavior: 'smooth' }));
      await wait(5000);

      // Send mismatched target prompt
      await chatInput.fill('Please scan 10.10.20.50 instead.');
      await wait(1500);
      if (sendBtn) await sendBtn.click();
      await wait(6000);

      // Scroll down to view TARGET SCOPE MISMATCH card
      await page.evaluate(() => window.scrollBy({ top: 400, behavior: 'smooth' }));
      await wait(6000);
    }
  } catch (e) {
    console.log('   Chat interaction notice:', e.message);
  }
  await wait(Math.max(2000, seg4Dur - 31000));

  // ── SEGMENT 5: Scanner Hub & Integrations ──────────────────────────
  console.log('🎬 Segment 5: Scanner Integration Hub & 7-Tool Diagnostic Matrix');
  const seg5Dur = (durations['05_scanners'] || 67) * 1000;
  await safeGoto('http://localhost:5173/integrations');
  await wait(3000);

  try {
    const zapTab = await page.$('button:has-text("OWASP ZAP")');
    if (zapTab) {
      await zapTab.click();
      await wait(3000);
    }
  } catch (e) {}

  // Scroll down to view the 7 tools
  await page.evaluate(() => window.scrollBy({ top: 450, behavior: 'smooth' }));
  await wait(7000);
  await page.evaluate(() => window.scrollBy({ top: -450, behavior: 'smooth' }));
  await wait(Math.max(2000, seg5Dur - 14000));

  // ── SEGMENT 6: Normalized Findings & Risk Scoring ─────────────────
  console.log('🎬 Segment 6: Vulnerability Findings & Mathematical Risk Prioritization');
  const seg6Dur = (durations['06_findings'] || 56) * 1000;
  await safeGoto('http://localhost:5173/vulnerabilities');
  await wait(4000);

  // Scroll through findings table
  await page.evaluate(() => window.scrollBy({ top: 350, behavior: 'smooth' }));
  await wait(6000);

  try {
    const viewBtn = await page.$('button:has-text("View"), button:has-text("Details"), tr[class*="cursor-pointer"]');
    if (viewBtn) {
      await viewBtn.click();
      await wait(4000);
      const closeBtn = await page.$('button:has-text("Close"), button[aria-label="Close"]');
      if (closeBtn) await closeBtn.click();
      await wait(1500);
    }
  } catch (e) {}
  await page.evaluate(() => window.scrollBy({ top: -350, behavior: 'smooth' }));
  await wait(Math.max(2000, seg6Dur - 16500));

  // ── SEGMENT 7: Human Approval Gateway ──────────────────────────────
  console.log('🎬 Segment 7: Human-in-the-Loop Approval Gateway');
  const seg7Dur = (durations['07_approvals'] || 48) * 1000;
  await safeGoto('http://localhost:5173/approvals');
  await wait(4000);

  // Scroll through approval queue
  await page.evaluate(() => window.scrollBy({ top: 350, behavior: 'smooth' }));
  await wait(6000);
  await page.evaluate(() => window.scrollBy({ top: -350, behavior: 'smooth' }));
  await wait(Math.max(2000, seg7Dur - 12000));

  // ── SEGMENT 8: Audit-Grade PDF Report ──────────────────────────────
  console.log('🎬 Segment 8: 20-Section VAPT PDF Generation');
  const seg8Dur = (durations['08_reports'] || 56) * 1000;
  await safeGoto('http://localhost:5173/reports');
  await wait(4000);

  try {
    const dlBtn = await page.$('button:has-text("Download Official PDF"), a:has-text("Download")');
    if (dlBtn) await dlBtn.hover();
  } catch (e) {}
  await wait(3000);
  await page.evaluate(() => window.scrollBy({ top: 350, behavior: 'smooth' }));
  await wait(4000);
  await page.evaluate(() => window.scrollBy({ top: -350, behavior: 'smooth' }));
  await wait(Math.max(2000, seg8Dur - 12000));

  // ── SEGMENT 9: Closing & Wrap-up ───────────────────────────────────
  console.log('🎬 Segment 9: Conclusion & SOC Operations Overview');
  const seg9Dur = (durations['09_closing'] || 42) * 1000;
  await safeGoto('http://localhost:5173/');
  await wait(4000);
  await page.evaluate(() => window.scrollBy({ top: 300, behavior: 'smooth' }));
  await wait(Math.max(2000, seg9Dur - 5000));

  // Close context to finish video
  console.log('\n3. Finalizing Playwright browser recording...');
  await context.close();
  await browser.close();

  // Find recorded WebM
  const webmFiles = fs.readdirSync(tempVideoDir).filter(f => f.endsWith('.webm'));
  if (webmFiles.length === 0) throw new Error('No recorded WebM file found in temp directory');
  const rawWebmPath = path.join(tempVideoDir, webmFiles[0]);
  console.log('   Raw WebM video captured:', rawWebmPath);

  // 4. Merge Video and Master Voiceover Audio
  console.log('\n4. Encoding final high-definition MP4 with synchronized Indian voiceover...');
  const finalMp4 = path.join(recordingsDir, 'AI-VAPT-AGENT_Complete_Demo_With_Voiceover.mp4');
  if (fs.existsSync(finalMp4)) fs.unlinkSync(finalMp4);

  const mergeCmd = `"${ffmpeg}" -y -i "${rawWebmPath}" -i "${masterAudio}" -c:v libx264 -pix_fmt yuv420p -preset fast -c:a aac -b:a 192k -shortest "${finalMp4}"`;
  execSync(mergeCmd);

  console.log('\n======================================================');
  console.log('🎉 DEMONSTRATION VIDEO GENERATED SUCCESSFULLY!');
  console.log('File:', finalMp4);
  console.log('File Size:', (fs.statSync(finalMp4).size / (1024 * 1024)).toFixed(2), 'MB');
  console.log('======================================================');

  // Copy to root workspace for easy access
  const rootMp4 = path.join(baseDir, 'AI-VAPT-AGENT_Complete_Demo_With_Voiceover.mp4');
  fs.copyFileSync(finalMp4, rootMp4);
  console.log('Copied to project root:', rootMp4);

  // Clean up raw webm
  fs.rmSync(tempVideoDir, { recursive: true, force: true });
}

main().catch(err => {
  console.error('\n❌ Error generating video:', err);
  process.exit(1);
});
