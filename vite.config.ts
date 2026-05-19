import build from '@hono/vite-build/cloudflare-pages'
import devServer from '@hono/vite-dev-server'
import adapter from '@hono/vite-dev-server/cloudflare'
import { defineConfig, type Plugin } from 'vite'
import { writeFileSync } from 'fs'
import { resolve } from 'path'

// 빌드 완료 후 _routes.json 을 확실히 덮어쓰는 플러그인
// Cloudflare Pages 에서 루트(/) 포함 모든 경로를 Worker 가 처리하도록 강제
function ensureRoutesJson(): Plugin {
  return {
    name: 'ensure-routes-json',
    closeBundle() {
      const routes = {
        version: 1,
        include: ['/*'],
        exclude: ['/static/*'],
      }
      writeFileSync(
        resolve(__dirname, 'dist/_routes.json'),
        JSON.stringify(routes, null, 2)
      )
      console.log('[ensure-routes-json] dist/_routes.json written')
    },
  }
}

export default defineConfig({
  plugins: [
    build(),
    devServer({
      adapter,
      entry: 'src/index.tsx'
    }),
    ensureRoutesJson(),
  ]
})
