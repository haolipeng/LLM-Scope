<script>
  import { groupedEvents } from '../stores/events';

  const palette = {
    ssl: '#c47f38',
    process: '#4b7a85',
    system: '#6a4f82',
    http_parser: '#2e8b57',
    sse_processor: '#cc4f5a',
    unknown: '#6c5b4c'
  };

  function groupColor(group) {
    if (!group.events || group.events.length === 0) {
      return palette.unknown;
    }
    const sample = group.events[0];
    return palette[sample.source] || palette.unknown;
  }
</script>

<section class="density">
  <h3>事件密度</h3>
  <div class="bars">
    {#if $groupedEvents.length === 0}
      <div class="empty">暂无数据</div>
    {:else}
      {#each $groupedEvents as group}
        <div
          class="bar"
          style={`height:${Math.min(80, group.events.length * 6 + 10)}px;background:${groupColor(group)}`}
          title={`${group.label}: ${group.events.length} 条`}
        ></div>
      {/each}
    {/if}
  </div>
</section>

<style>
  .density {
    margin-top: 1.2rem;
  }

  h3 {
    margin: 0 0 0.6rem;
    font-size: 0.9rem;
  }

  .bars {
    display: flex;
    gap: 0.3rem;
    align-items: flex-end;
    min-height: 90px;
    padding: 0.5rem;
    background: rgba(255, 255, 255, 0.7);
    border-radius: 12px;
    border: 1px solid rgba(0, 0, 0, 0.08);
  }

  .bar {
    flex: 1;
    border-radius: 6px 6px 2px 2px;
    opacity: 0.85;
  }

  .empty {
    color: #8b6f55;
    font-size: 0.75rem;
  }
</style>
