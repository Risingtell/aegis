import sharp from "sharp";
import { readFile } from "node:fs/promises";

const logo = await readFile("brand/logo.svg");
const cover = await readFile("brand/cover.svg");

for (const size of [256, 512, 1024]) {
  await sharp(logo, { density: 400 }).resize(size, size).png().toFile(`brand/logo-${size}.png`);
}
await sharp(cover, { density: 200 }).resize(1280, 640).png().toFile("brand/cover.png");
console.log("rendered: logo-256/512/1024.png, cover.png");
