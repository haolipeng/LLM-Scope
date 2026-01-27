<script>
  export let event = null;
</script>

<section class="detail">
  {#if !event}
    <div class="placeholder">选择一条事件查看详情</div>
  {:else}
    <h2>事件详情</h2>
    <p><strong>来源:</strong> {event.source}</p>
    <p><strong>PID:</strong> {event.pid}</p>
    <p><strong>进程:</strong> {event.comm}</p>
    <p><strong>时间:</strong> {event.timestamp_unix_ms ? new Date(event.timestamp_unix_ms).toLocaleString() : event.timestamp_ns}</p>
    {#if event.source === 'tool_call' && event.data?.tool_name}
      <p><strong>工具:</strong> {event.data.tool_name}</p>
    {/if}
    <pre>{JSON.stringify(event.data, null, 2)}</pre>
  {/if}
</section>

<style>
  .detail {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .placeholder {
    color: #8a715c;
    text-align: center;
    padding: 2rem 1rem;
  }

  pre {
    background: #f1e6d7;
    padding: 0.8rem;
    border-radius: 12px;
    overflow-x: auto;
    font-size: 0.75rem;
  }
</style>
