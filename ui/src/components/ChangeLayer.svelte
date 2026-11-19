<script lang="ts">
  // The review panel, shown while a review is open. The app shell and the
  // screen tests mount this one place.
  import { changes } from '../lib/changes.svelte';
  import ReviewPanel from './ReviewPanel.svelte';
</script>

{#if changes.panel}
  <ReviewPanel drafts={changes.panel} />
{/if}
