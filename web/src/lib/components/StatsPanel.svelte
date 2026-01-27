<script>
  import { stats } from '../stores/events';

  const palette = {
    ssl: '#c47f38',
    process: '#4b7a85',
    system: '#6a4f82',
    http_parser: '#2e8b57',
    sse_processor: '#cc4f5a',
    tool_call: '#8a6f3d',
    unknown: '#6c5b4c'
  };
</script>

<section class="stats">
  <h2>事件概览</h2>
  <div class="cards">
    <div class="card">
      <strong>{$stats.total}</strong>
      <span>总事件</span>
    </div>
    <div class="card">
      <strong>{$stats.lastMinute}</strong>
      <span>最近 60 秒</span>
    </div>
  </div>
  <div class="sources">
    {#each Object.entries($stats.bySource) as [source, count]}
      <div class="row">
        <span class="dot" style={`background:${palette[source] || palette.unknown}`}></span>
        <span class="label">{source}</span>
        <span class="value">{count}</span>
      </div>
    {/each}
  </div>
</section>

<style>
  .stats {
    margin-top: 1.5rem;
    background: rgba(255, 255, 255, 0.65);
    border-radius: 16px;
    padding: 1rem;
    border: 1px solid rgba(0, 0, 0, 0.08);
  }

  h2 {
    margin: 0 0 1rem;
    font-size: 1rem;
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 0.8rem;
  }

  .card {
    background: #fffdf8;
    border-radius: 12px;
    padding: 0.8rem;
    text-align: center;
  }

  .card strong {
    font-size: 1.4rem;
  }

  .sources {
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.8rem;
  }

  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    margin-right: 0.5rem;
  }

  .label {
    flex: 1;
  }

  .value {
    font-weight: 600;
  }
</style>
