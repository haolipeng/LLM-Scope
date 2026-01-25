<script>
  import {
    filterText,
    sourceFilter,
    commFilter,
    pidFilter,
    timeStart,
    timeEnd,
    timeWindowMinutes,
    sampleStep,
    bucketSizeSeconds,
    sources,
    comms,
    pids,
    viewMode,
    paused,
    events
  } from '../stores/events';

  const windowOptions = [
    { label: '全部', value: 0 },
    { label: '5 分钟', value: 5 },
    { label: '15 分钟', value: 15 },
    { label: '1 小时', value: 60 },
    { label: '6 小时', value: 360 }
  ];

  const bucketOptions = [
    { label: '不分桶', value: 0 },
    { label: '10 秒', value: 10 },
    { label: '30 秒', value: 30 },
    { label: '1 分钟', value: 60 },
    { label: '5 分钟', value: 300 }
  ];

  function toggleSource(source) {
    sourceFilter.update((list) => {
      if (list.includes(source)) {
        return list.filter((item) => item !== source);
      }
      return [...list, source];
    });
  }

  function clearFilters() {
    filterText.set('');
    sourceFilter.set([]);
    commFilter.set('');
    pidFilter.set('');
    timeStart.set('');
    timeEnd.set('');
    timeWindowMinutes.set(0);
    sampleStep.set(1);
    bucketSizeSeconds.set(0);
  }

  function togglePause() {
    paused.update((value) => !value);
  }

  function clearEvents() {
    events.set([]);
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify($events, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'agentsight-events.json';
    link.click();
    URL.revokeObjectURL(url);
  }

  function exportJSONL() {
    const lines = $events.map((event) => JSON.stringify(event)).join('\n');
    const blob = new Blob([lines], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'agentsight-events.jsonl';
    link.click();
    URL.revokeObjectURL(url);
  }
</script>

<section class="filter">
  <h2>过滤与控制</h2>

  <label>
    <span>关键词</span>
    <input
      type="text"
      placeholder="pid / comm / source / 内容"
      on:input={(e) => filterText.set(e.target.value)}
      value={$filterText}
    />
  </label>

  <div class="group">
    <span>时间范围</span>
    <div class="time-range">
      <input type="datetime-local" value={$timeStart} on:input={(e) => timeStart.set(e.target.value)} />
      <input type="datetime-local" value={$timeEnd} on:input={(e) => timeEnd.set(e.target.value)} />
    </div>
  </div>

  <div class="group">
    <span>时间窗口</span>
    <div class="window-pills">
      {#each windowOptions as option}
        <button
          type="button"
          class:active={$timeWindowMinutes === option.value}
          on:click={() => timeWindowMinutes.set(option.value)}
        >
          {option.label}
        </button>
      {/each}
    </div>
  </div>

  <div class="group">
    <span>分桶</span>
    <div class="window-pills">
      {#each bucketOptions as option}
        <button
          type="button"
          class:active={$bucketSizeSeconds === option.value}
          on:click={() => bucketSizeSeconds.set(option.value)}
        >
          {option.label}
        </button>
      {/each}
    </div>
  </div>

  <div class="group">
    <span>采样</span>
    <div class="sample">
      <input
        type="range"
        min="1"
        max="10"
        value={$sampleStep}
        on:input={(e) => sampleStep.set(Number(e.target.value))}
      />
      <span>每 {Math.max(1, $sampleStep)} 条取 1 条</span>
    </div>
  </div>

  <div class="group">
    <span>来源</span>
    <div class="chips">
      {#each $sources as source}
        <button
          type="button"
          class:active={$sourceFilter.includes(source)}
          on:click={() => toggleSource(source)}
        >
          {source}
        </button>
      {/each}
    </div>
  </div>

  <div class="group">
    <span>进程名</span>
    <select on:change={(e) => commFilter.set(e.target.value)} value={$commFilter}>
      <option value="">全部</option>
      {#each $comms as comm}
        <option value={comm}>{comm}</option>
      {/each}
    </select>
  </div>

  <div class="group">
    <span>PID</span>
    <select on:change={(e) => pidFilter.set(e.target.value)} value={$pidFilter}>
      <option value="">全部</option>
      {#each $pids as pid}
        <option value={pid}>{pid}</option>
      {/each}
    </select>
  </div>

  <div class="group">
    <span>视图</span>
    <div class="view-toggle">
      <button type="button" class:active={$viewMode === 'detail'} on:click={() => viewMode.set('detail')}>详情</button>
      <button type="button" class:active={$viewMode === 'compact'} on:click={() => viewMode.set('compact')}>紧凑</button>
    </div>
  </div>

  <div class="actions">
    <button type="button" on:click={togglePause}>{$paused ? '继续' : '暂停'}</button>
    <button type="button" on:click={clearFilters}>重置过滤</button>
    <button type="button" on:click={clearEvents}>清空事件</button>
    <button type="button" on:click={exportJSON}>导出 JSON</button>
    <button type="button" on:click={exportJSONL}>导出 JSONL</button>
  </div>
</section>

<style>
  .filter h2 {
    margin: 0 0 1rem;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    font-size: 0.85rem;
  }

  input,
  select {
    padding: 0.6rem 0.8rem;
    border-radius: 12px;
    border: 1px solid #d4c4a3;
    background: #fffdf8;
  }

  .group {
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    font-size: 0.8rem;
  }

  .time-range {
    display: grid;
    gap: 0.5rem;
  }

  .window-pills,
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .window-pills button,
  .chips button {
    border: 1px solid #cbb59b;
    background: #fff7ea;
    border-radius: 999px;
    padding: 0.3rem 0.8rem;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    cursor: pointer;
  }

  .window-pills button.active,
  .chips button.active {
    background: #c47f38;
    color: #fff;
    border-color: #c47f38;
  }

  .sample {
    display: grid;
    gap: 0.4rem;
  }

  .sample input {
    padding: 0;
  }

  .sample span {
    font-size: 0.75rem;
    color: #6f5a44;
  }

  .view-toggle {
    display: flex;
    gap: 0.5rem;
  }

  .view-toggle button {
    flex: 1;
    padding: 0.4rem 0.6rem;
    border-radius: 10px;
    border: 1px solid #bda88c;
    background: #f8efe2;
    cursor: pointer;
  }

  .view-toggle button.active {
    background: #4b7a85;
    color: #fff;
  }

  .actions {
    margin-top: 1.2rem;
    display: grid;
    gap: 0.6rem;
  }

  .actions button {
    padding: 0.5rem 0.8rem;
    border-radius: 12px;
    border: none;
    background: #1a1a1a;
    color: #f5f0e5;
    cursor: pointer;
  }

  .actions button:last-child {
    background: #a64a4a;
  }
</style>
