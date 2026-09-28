/**
 * Records one webm per scene of the ECDAT dashboard and the evidence site.
 *
 *   node record.js            # all scenes
 *   node record.js overview   # one scene
 *
 * Each scene gets its own browser context so each gets its own video file. Movements are slowed
 * deliberately - this is footage for a demo video, not a test run.
 */
const { chromium } = require('playwright')
const fs = require('fs')
const path = require('path')

const BASE = process.env.ECDAT_BASE || 'http://127.0.0.1:8733'
const OUT = path.join(__dirname, 'raw')
const SIZE = { width: 1440, height: 900 }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** Move the mouse in a human-ish arc, so the pointer does not teleport in the footage. */
async function glide(page, x, y, steps = 26) {
  await page.mouse.move(x, y, { steps })
  await sleep(220)
}

async function centreOf(page, selector, nth = 0) {
  const box = await page.locator(selector).nth(nth).boundingBox()
  if (!box) throw new Error(`no box for ${selector}`)
  return { x: box.x + box.width / 2, y: box.y + box.height / 2, box }
}

const scenes = {
  // 1 - the verdict, and what happens when the quantum year moves
  async overview(page) {
    await page.goto(`${BASE}/dashboard/index.html#overview`)
    await page.waitForSelector('.verdict .headline')
    await sleep(2200)
    await glide(page, 700, 300)
    await sleep(900)
    const seg = await centreOf(page, '.ribbon .seg', 1)          // act now
    await glide(page, seg.x, seg.y)
    await sleep(1400)
    const slider = await centreOf(page, '.zslider input[type=range]')
    await glide(page, slider.x, slider.y)
    await page.mouse.down()
    for (let i = 0; i <= 10; i++) {                              // drag Z back towards 2032
      await page.mouse.move(slider.x - i * (slider.box.width / 22), slider.y, { steps: 3 })
      await sleep(90)
    }
    await page.mouse.up()
    await sleep(2600)                                            // tiers recompute, EXPOSED appears
    await page.mouse.wheel(0, 420)
    await sleep(1800)
  },

  // 2 - every finding, filtered, down to the evidence that proved one
  async findings(page) {
    await page.goto(`${BASE}/dashboard/index.html#assets`)
    await page.waitForSelector('table.findings tbody tr')
    await sleep(1600)
    const search = await centreOf(page, 'input[type=search]')
    await glide(page, search.x, search.y)
    await page.mouse.click(search.x, search.y)
    for (const ch of 'RSA') { await page.keyboard.type(ch); await sleep(260) }
    await sleep(1800)
    const row = await centreOf(page, 'table.findings tbody tr', 0)
    await glide(page, row.x, row.y)
    await sleep(700)
    await page.mouse.click(row.x, row.y)                         // drawer: evidence, agility, plan
    await sleep(2600)
    await page.mouse.wheel(0, 700)
    await sleep(2200)
    await page.keyboard.press('Escape')
    await sleep(1200)
  },

  // 3 - risk against how hard the fix is
  async matrix(page) {
    await page.goto(`${BASE}/dashboard/index.html#matrix`)
    await page.waitForSelector('svg.chart circle')
    await sleep(1800)
    const dots = page.locator('svg.chart circle')
    const n = Math.min(await dots.count(), 6)
    for (let i = 0; i < n; i++) {
      const b = await dots.nth(i * 2).boundingBox()
      if (!b) continue
      await glide(page, b.x + b.width / 2, b.y + b.height / 2, 18)
      await sleep(620)
    }
    const cb = await centreOf(page, 'input[type=checkbox]')
    await glide(page, cb.x, cb.y)
    await page.mouse.click(cb.x, cb.y)                           // show SAFE too
    await sleep(2200)
  },

  // 4 - what fits the budget, and what changes when the budget does
  async plan(page) {
    await page.goto(`${BASE}/dashboard/index.html#plan`)
    await page.waitForSelector('svg.chart path')
    await sleep(2000)
    const eng = page.locator('input[type=number]').first()
    const b = await eng.boundingBox()
    await glide(page, b.x + b.width / 2, b.y + b.height / 2)
    await eng.click({ clickCount: 3 })
    await page.keyboard.type('8')
    await sleep(700)
    const btn = await centreOf(page, 'button.primary')
    await glide(page, btn.x, btn.y)
    await page.mouse.click(btn.x, btn.y)
    await sleep(2600)
    await page.mouse.wheel(0, 900)
    await sleep(2400)
  },

  // 5 - the published evidence a reviewer opens
  async evidence(page) {
    await page.goto(`${BASE}/index.html`)
    await page.waitForSelector('.artefact')
    await sleep(2000)
    const row = await centreOf(page, '.artefact', 0)
    await glide(page, row.x, row.y)
    await sleep(1000)
    await page.mouse.click(row.x, row.y)                          // the whole row is the link
    await page.waitForSelector('#t tbody tr', { timeout: 15000 })
    await sleep(2200)
    await page.mouse.wheel(0, 900)
    await sleep(1600)
    const filt = await centreOf(page, '.filters button', 1)
    await glide(page, filt.x, filt.y)
    await page.mouse.click(filt.x, filt.y)                        // filter to one category
    await sleep(2400)
    await page.mouse.wheel(0, 700)
    await sleep(1800)
  },
}

;(async () => {
  const want = process.argv.slice(2)
  const names = want.length ? want : Object.keys(scenes)
  fs.mkdirSync(OUT, { recursive: true })
  const browser = await chromium.launch()
  for (const name of names) {
    const dir = path.join(OUT, name)
    fs.rmSync(dir, { recursive: true, force: true })
    const ctx = await browser.newContext({
      viewport: SIZE,
      deviceScaleFactor: 2,
      recordVideo: { dir, size: SIZE },
      colorScheme: 'dark',
    })
    const page = await ctx.newPage()
    process.stdout.write(`recording ${name} ... `)
    try {
      await scenes[name](page)
    } catch (e) {
      process.stdout.write(`FAILED: ${e.message} `)
    }
    await ctx.close()
    const file = fs.readdirSync(dir).find((f) => f.endsWith('.webm'))
    console.log(file ? `${(fs.statSync(path.join(dir, file)).size / 1e6).toFixed(1)} MB` : 'no video')
  }
  await browser.close()
})()
