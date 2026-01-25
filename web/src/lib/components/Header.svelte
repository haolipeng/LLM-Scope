<script>
  import { stats } from '../stores/events';
  export let connected = false;
</script>

<header class="header">
  <div>
    <p class="eyebrow">AgentSight</p>
    <h1>实时 AI Agent 观测台</h1>
    <p class="subtitle">聚合 SSL / Process / System 事件，秒级追踪链路。</p>
  </div>
  <div class="status">
    <div class="status-dot" class:online={connected}></div>
    <div>
      <strong>{connected ? 'SSE 已连接' : 'SSE 断开'}</strong>
      <span>{$stats.total} 条事件 · 近一分钟 {$stats.lastMinute} 条</span>
    </div>
  </div>
</header>

<style>
  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem 2rem 0;
  }

  .eyebrow {
    font-size: 0.75rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: #6b4b2a;
    margin: 0;
  }

  h1 {
    font-size: 2.2rem;
    margin: 0.4rem 0 0.2rem;
  }

  .subtitle {
    margin: 0;
    color: #5b4a3a;
  }

  .status {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    background: #1a1a1a;
    color: #f5f0e5;
    padding: 0.6rem 1.1rem;
    border-radius: 999px;
    font-size: 0.85rem;
  }

  .status span {
    display: block;
    font-size: 0.7rem;
    color: #c5b7a6;
  }

  .status-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: #a56d48;
  }

  .status-dot.online {
    background: #2ecc71;
  }

  @media (max-width: 1024px) {
    .header {
      flex-direction: column;
      align-items: flex-start;
      gap: 1rem;
      padding: 1.5rem 1rem 0;
    }
  }
</style>
