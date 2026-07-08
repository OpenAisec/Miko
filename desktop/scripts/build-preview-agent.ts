import { $ } from 'bun'
import { readFile, rename, rm } from 'node:fs/promises'

const outfile = './src-tauri/resources/preview-agent.js'
const tmpfile = `${outfile}.${process.pid}.tmp`

await $`bun build ./src/preview-agent/index.ts --outfile=${tmpfile} --format=iife --minify`

try {
  const [current, next] = await Promise.all([
    readFile(outfile),
    readFile(tmpfile),
  ])
  if (current.equals(next)) {
    await rm(tmpfile, { force: true })
    console.log('preview-agent.js unchanged')
    process.exit(0)
  }
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
    await rm(tmpfile, { force: true })
    throw error
  }
}

await rename(tmpfile, outfile)
console.log('preview-agent.js built')
