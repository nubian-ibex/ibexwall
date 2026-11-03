import { mount } from 'svelte';
import './styles/base.css';
import App from './App.svelte';
import PromptWindow from './components/PromptWindow.svelte';

// `ibexwall --prompt` opens the question alone, in a small window.
const alone = new URLSearchParams(globalThis.location?.search ?? '').get('window') === 'prompt';
mount(alone ? PromptWindow : App, { target: document.getElementById('app')! });
