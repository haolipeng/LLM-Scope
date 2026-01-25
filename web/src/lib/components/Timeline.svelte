<script>
  import EventCard from './EventCard.svelte';

  export let groups = [];
</script>

<section class="timeline">
  {#if !groups || groups.length === 0}
    <div class="empty">暂无事件，等待 SSE 推送...</div>
  {:else}
    {#each groups as group}
      <div class="bucket">
        <div class="bucket-header">
          <span>{group.label}</span>
          <span>{group.events.length} 条</span>
        </div>
        <div class="bucket-body">
          {#each group.events as event (event.timestamp_ns)}
            <EventCard {event} />
          {/each}
        </div>
      </div>
    {/each}
  {/if}
</section>

<style>
  .timeline {
    display: flex;
    flex-direction: column;
    gap: 1.2rem;
  }

  .bucket {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .bucket-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #1a1a1a;
    color: #f5f0e5;
    padding: 0.4rem 0.8rem;
    border-radius: 999px;
    font-size: 0.8rem;
  }

  .bucket-body {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .empty {
    padding: 2rem;
    text-align: center;
    color: #8b6f55;
  }
</style>
