<script>
  import { selectedEvent, viewMode } from '../stores/events';

  export let event;

  const colorMap = {
    ssl: '#c47f38',
    process: '#4b7a85',
    system: '#6a4f82',
    http_parser: '#2e8b57',
    sse_processor: '#cc4f5a'
  };

  const color = colorMap[event.source] || '#6c5b4c';

  function select() {
    selectedEvent.set(event);
  }

  function summary(data) {
    if (!data) return '';
    if (typeof data === 'string') {
      return data;
    }
    if (Array.isArray(data)) {
      return `Array(${data.length})`;
    }
    if (data.method && data.path) {
      return `${data.method} ${data.path}`;
    }
    if (data.event) {
      return `${data.event}`;
    }
    if (data.type) {
      return `${data.type}`;
    }
    return Object.keys(data).slice(0, 4).join(', ');
  }
</script>

<button class="card" type="button" on:click={select}>
  <header>
    <span class="pill" style={`background:${color}`}>{event.source}</span>
    <span class="meta">PID {event.pid} · {event.comm}</span>
    <span class="time">{event.timestamp_unix_ms ? new Date(event.timestamp_unix_ms).toLocaleTimeString() : event.timestamp_ns}</span>
  </header>
  {#if $viewMode === 'compact'}
    <p class="summary">{summary(event.data)}</p>
  {:else}
    <pre>{JSON.stringify(event.data, null, 2)}</pre>
  {/if}
</button>

<style>
  .card {
    text-align: left;
    width: 100%;
    border: 1px solid rgba(0, 0, 0, 0.08);
    border-radius: 16px;
    padding: 1rem;
    background: rgba(255, 255, 255, 0.9);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.08);
    cursor: pointer;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
  }

  .card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.12);
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    margin-bottom: 0.8rem;
  }

  .pill {
    padding: 0.2rem 0.6rem;
    border-radius: 999px;
    color: #fff;
    font-size: 0.7rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  .meta {
    font-size: 0.8rem;
    color: #5e4b3d;
    flex: 1;
  }

  .time {
    font-size: 0.75rem;
    color: #8b7563;
  }

  pre {
    margin: 0;
    background: #f8f2e8;
    padding: 0.8rem;
    border-radius: 12px;
    overflow-x: auto;
    font-size: 0.75rem;
  }

  .summary {
    margin: 0;
    font-size: 0.9rem;
    color: #4b3e33;
  }
</style>
