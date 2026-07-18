<script setup>
import { computed, onMounted, ref } from 'vue'

const configured = ref(true)
const authenticated = ref(false)
const overview = ref({})
const metrics = ref([])
const range = ref('1h')
const error = ref('')
const form = ref({ username: '', password: '' })

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || '请求失败')
  return data
}

async function loadDashboard() {
  overview.value = await api('/api/overview')
  metrics.value = (await api(`/api/metrics?range=${range.value}`)).points
  authenticated.value = true
}

async function submit() {
  error.value = ''
  try {
    await api(configured.value ? '/api/login' : '/api/setup', {
      method: 'POST',
      body: JSON.stringify(form.value)
    })
    await loadDashboard()
  } catch (e) {
    error.value = e.message
  }
}

const latest = computed(() => overview.value.latest || {})

onMounted(async () => {
  const status = await api('/api/status')
  configured.value = status.configured
  if (configured.value) {
    try { await loadDashboard() } catch {}
  }
})
</script>

<template>
  <div v-if="!authenticated" class="login-page">
    <div class="login-card">
      <div class="brand login-brand">
        <div class="brand-mark">T</div>
        <div><strong>TryAllFun</strong><span>SERVER PANEL</span></div>
      </div>
      <h1>{{ configured ? '欢迎回来' : '初始化管理面板' }}</h1>
      <p>自由、私有，无需手机号或实名。</p>
      <form @submit.prevent="submit">
        <label>管理员账号<input v-model="form.username" required minlength="3"></label>
        <label>管理员密码<input v-model="form.password" type="password" required></label>
        <div class="form-error">{{ error }}</div>
        <button class="primary" type="submit">{{ configured ? '安全登录' : '创建并进入面板' }}</button>
      </form>
    </div>
  </div>

  <div v-else class="app-shell">
    <aside>
      <div class="brand"><div class="brand-mark">T</div><div><strong>TryAllFun</strong><span>SERVER PANEL</span></div></div>
      <nav><button class="active"><i>⌁</i>总览</button><button><i>◇</i>应用商店</button><button><i>▱</i>文件管理</button><button><i>⛨</i>防火墙</button><button><i>◉</i>安全中心</button></nav>
    </aside>
    <main>
      <header><div class="crumb">TryAllFun Panel / 总览</div></header>
      <section id="content">
        <div class="page-head"><div><h1>服务器总览</h1><p>{{ overview.hostname }} · {{ overview.os }}</p></div></div>
        <div class="metrics">
          <article v-for="item in [
            ['CPU 使用率', latest.cpu],
            ['内存使用率', latest.memory],
            ['磁盘使用率', latest.disk],
            ['实时网络 KB/s', latest.network]
          ]" :key="item[0]" class="metric-card">
            <div class="metric-top"><span>{{ item[0] }}</span></div>
            <div class="metric-value">{{ Number(item[1] || 0).toFixed(1) }}</div>
          </article>
        </div>
        <article class="panel">
          <div class="panel-title"><div><h2>资源趋势</h2><p>{{ metrics.length }} 个聚合采样点</p></div>
            <div class="range"><button v-for="r in ['1h','6h','24h','7d','30d']" :key="r" :class="{active:range===r}" @click="range=r;loadDashboard()">{{ r }}</button></div>
          </div>
        </article>
      </section>
    </main>
  </div>
</template>

