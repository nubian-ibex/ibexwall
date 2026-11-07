<script lang="ts">
  import Bot from '@lucide/svelte/icons/bot';
  import Box from '@lucide/svelte/icons/box';
  import BrickWall from '@lucide/svelte/icons/brick-wall';
  import ClipboardList from '@lucide/svelte/icons/clipboard-list';
  import Clock from '@lucide/svelte/icons/clock';
  import Globe from '@lucide/svelte/icons/globe';
  import HardDrive from '@lucide/svelte/icons/hard-drive';
  import LayoutGrid from '@lucide/svelte/icons/layout-grid';
  import Monitor from '@lucide/svelte/icons/monitor';
  import LockKeyhole from '@lucide/svelte/icons/lock-keyhole';
  import Lock from '@lucide/svelte/icons/lock';
  import Radio from '@lucide/svelte/icons/radio';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import Settings from '@lucide/svelte/icons/settings';
  import ShieldCheck from '@lucide/svelte/icons/shield-check';
  import UserLock from '@lucide/svelte/icons/user-lock';
  import Check from '@lucide/svelte/icons/check';
  import TriangleAlert from '@lucide/svelte/icons/triangle-alert';
  import CircleQuestionMark from '@lucide/svelte/icons/circle-question-mark';
  import BadgeCheck from '@lucide/svelte/icons/badge-check';

  const icons = {
    bot: Bot,
    box: Box,
    'brick-wall': BrickWall,
    'badge-check': BadgeCheck,
    'clipboard-list': ClipboardList,
    clock: Clock,
    globe: Globe,
    'hard-drive': HardDrive,
    'layout-grid': LayoutGrid,
    monitor: Monitor,
    'lock-keyhole': LockKeyhole,
    lock: Lock,
    radio: Radio,
    'refresh-cw': RefreshCw,
    settings: Settings,
    'shield-check': ShieldCheck,
    'user-lock': UserLock,
    check: Check,
    'triangle-alert': TriangleAlert,
    'circle-question-mark': CircleQuestionMark,
  } as const;

  // Icons are decorative: meaning is always carried by text, never colour or
  // shape alone.
  let { name, size = 20 }: { name: string; size?: number } = $props();
  const Component = $derived((icons as Record<string, typeof Box>)[name] ?? CircleQuestionMark);
</script>

<Component {size} strokeWidth={1.9} aria-hidden="true" />
