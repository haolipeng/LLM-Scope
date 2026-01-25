<script>
  import { onMount } from 'svelte';
  import Timeline from './lib/components/Timeline.svelte';
  import Header from './lib/components/Header.svelte';
  import Filter from './lib/components/Filter.svelte';
  import EventDetail from './lib/components/EventDetail.svelte';
  import StatsPanel from './lib/components/StatsPanel.svelte';
  import DensityBar from './lib/components/DensityBar.svelte';
  import { appendEvent, groupedEvents, selectedEvent, paused, now } from './lib/stores/events';

  let connected = false;
  let reconnectTimer = null;

  function setupStream() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
    }

    const source = new EventSource('/api/events/stream');
    source.onopen = () => {
      connected = true;
    };
    source.onerror = () => {
      connected = false;
      source.close();
      reconnectTimer = setTimeout(setupStream, 2000);
    };
    source.onmessage = (e) => {
      if ($paused) {
        return;
      }
      try {
        const payload = JSON.parse(e.data);
        appendEvent(payload);
      } catch (err) {
        console.error('Failed to parse event', err);
      }
    };
  }

  onMount(() => {
    const timer = setInterval(() => {
      now.set(Date.now());
    }, 1000);

    setupStream();

    fetch('/api/events')
      .then((res) => res.text())
      .then((text) => {
        if (!text.trim()) {
          return;
        }
        const lines = text.split('\n').filter(Boolean);
        lines.forEach((line) => {
          try {
            appendEvent(JSON.parse(line));
          } catch (err) {
            console.warn('Failed to parse history event', err);
          }
        });
      })
      .catch((err) => console.error('Failed to load history', err));

    return () => {
      clearInterval(timer);
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
    };
  });
</script>

<main class="page">
  <Header {connected} />
  <section class="layout">
    <aside class="sidebar">
      <Filter />
      <StatsPanel />
    </aside>
    <section class="content">
      <DensityBar />
      <Timeline groups={$groupedEvents} />
    </section>
    <aside class="detail">
      <EventDetail event={$selectedEvent} />
    </aside>
  </section>
</main>

<style>
  :global(body) {
    margin: 0;
    font-family: "IBM Plex Mono", "Fira Code", monospace;
    background: radial-gradient(circle at top, #f3f0e7, #e7dcc8 55%, #d8c5a6 100%);
    color: #1a1a1a;
  }

  .page {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .layout {
    display: grid;
    grid-template-columns: 260px 1fr 340px;
    gap: 1.5rem;
    padding: 0 2rem 2rem;
  }

  .sidebar,
  .detail {
    background: rgba(255, 255, 255, 0.7);
    border: 1px solid rgba(0, 0, 0, 0.08);
    border-radius: 18px;
    padding: 1rem;
    backdrop-filter: blur(6px);
  }

  .content {
    background: rgba(255, 255, 255, 0.4);
    border: 1px solid rgba(0, 0, 0, 0.1);
    border-radius: 24px;
    padding: 1rem 1.5rem;
  }

  @media (max-width: 1024px) {
    .layout {
      grid-template-columns: 1fr;
      padding: 0 1rem 2rem;
    }
  }
</style>
