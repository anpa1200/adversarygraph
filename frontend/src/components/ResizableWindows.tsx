import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';

const WINDOW_SELECTOR = [
  'main section[class*="border"]',
  'main article[class*="border"]',
  'main aside[class*="border"]',
  '[data-resizable-window="true"]',
  '[class*="fixed"] [class*="border"][class*="bg-"]',
  '[class*="fixed"] [class*="border"][class*="shadow-2xl"]',
].join(',');

const HANDLE_DIRECTIONS = ['n', 'e', 's', 'w', 'ne', 'nw', 'se', 'sw'] as const;
const MIN_WIDTH = 260;
const MIN_HEIGHT = 120;

type ResizeDirection = (typeof HANDLE_DIRECTIONS)[number];

export function ResizableWindows() {
  const location = useLocation();

  useEffect(() => {
    const root = document.body;

    let frame = 0;
    const queueEnhance = () => {
      window.cancelAnimationFrame(frame);
      frame = window.requestAnimationFrame(() => enhanceResizableWindows(root));
    };

    queueEnhance();
    const observer = new MutationObserver(queueEnhance);
    observer.observe(root, { childList: true, subtree: true });

    return () => {
      observer.disconnect();
      window.cancelAnimationFrame(frame);
      cleanupResizableWindows(root);
    };
  }, [location.pathname]);

  return null;
}

function enhanceResizableWindows(root: Element) {
  const candidates = Array.from(root.querySelectorAll<HTMLElement>(WINDOW_SELECTOR));
  candidates.forEach(element => {
    if (!isResizableCandidate(element)) return;
    element.dataset.agResizableWindow = 'true';
    element.classList.add('ag-resizable-window');
    HANDLE_DIRECTIONS.forEach(direction => addHandle(element, direction));
  });
}

function cleanupResizableWindows(root: Element) {
  root.querySelectorAll('.ag-resize-handle').forEach(handle => handle.remove());
  root.querySelectorAll<HTMLElement>('.ag-resizable-window').forEach(element => {
    delete element.dataset.agResizableWindow;
    element.classList.remove('ag-resizable-window', 'ag-resized-window');
  });
  document.body.classList.remove('ag-window-resizing');
}

function isResizableCandidate(element: HTMLElement) {
  if (element.dataset.agResizableWindow === 'true') return false;
  if (element.dataset.noResizableWindow === 'true') return false;
  if (element.closest('[data-no-resizable-window="true"]')) return false;
  if (element.closest('button, a, input, select, textarea, table, nav, header, footer')) return false;

  const rect = element.getBoundingClientRect();
  if (rect.width < MIN_WIDTH || rect.height < 72) return false;
  return true;
}

function addHandle(element: HTMLElement, direction: ResizeDirection) {
  const handle = document.createElement('button');
  handle.type = 'button';
  handle.tabIndex = -1;
  handle.className = `ag-resize-handle ag-resize-${direction}`;
  handle.dataset.direction = direction;
  handle.setAttribute('aria-label', `Resize ${windowLabel(element)}`);
  handle.addEventListener('pointerdown', event => startResize(event, element, direction));
  handle.addEventListener('dblclick', event => {
    event.preventDefault();
    event.stopPropagation();
    element.style.width = '';
    element.style.height = '';
    element.classList.remove('ag-resized-window');
  });
  element.append(handle);
}

function startResize(event: PointerEvent, element: HTMLElement, direction: ResizeDirection) {
  if (event.button !== 0) return;
  event.preventDefault();
  event.stopPropagation();

  const handle = event.currentTarget;
  if (handle instanceof HTMLElement) handle.setPointerCapture(event.pointerId);

  const rect = element.getBoundingClientRect();
  const startX = event.clientX;
  const startY = event.clientY;
  const startWidth = rect.width;
  const startHeight = rect.height;
  const maxWidth = Math.max(startWidth, Math.min(2200, window.innerWidth * 1.4));
  const maxHeight = Math.max(startHeight, Math.min(2200, window.innerHeight * 1.8));

  document.body.classList.add('ag-window-resizing');

  const onMove = (moveEvent: PointerEvent) => {
    const nextWidth = nextSize({
      current: startWidth,
      positiveDelta: moveEvent.clientX - startX,
      negativeDelta: startX - moveEvent.clientX,
      min: MIN_WIDTH,
      max: maxWidth,
      growsPositive: direction.includes('e'),
      growsNegative: direction.includes('w'),
    });
    const nextHeight = nextSize({
      current: startHeight,
      positiveDelta: moveEvent.clientY - startY,
      negativeDelta: startY - moveEvent.clientY,
      min: MIN_HEIGHT,
      max: maxHeight,
      growsPositive: direction.includes('s'),
      growsNegative: direction.includes('n'),
    });

    if (nextWidth !== null) element.style.width = `${Math.round(nextWidth)}px`;
    if (nextHeight !== null) element.style.height = `${Math.round(nextHeight)}px`;
    element.classList.add('ag-resized-window');
  };

  const onUp = () => {
    document.body.classList.remove('ag-window-resizing');
    window.removeEventListener('pointermove', onMove);
    window.removeEventListener('pointerup', onUp);
    window.removeEventListener('pointercancel', onUp);
  };

  window.addEventListener('pointermove', onMove);
  window.addEventListener('pointerup', onUp);
  window.addEventListener('pointercancel', onUp);
}

function nextSize({
  current,
  positiveDelta,
  negativeDelta,
  min,
  max,
  growsPositive,
  growsNegative,
}: {
  current: number;
  positiveDelta: number;
  negativeDelta: number;
  min: number;
  max: number;
  growsPositive: boolean;
  growsNegative: boolean;
}) {
  if (!growsPositive && !growsNegative) return null;
  const delta = growsPositive ? positiveDelta : negativeDelta;
  return Math.min(max, Math.max(min, current + delta));
}

function windowLabel(element: HTMLElement) {
  const title = element.querySelector('h1, h2, h3, [class*="font-semibold"]')?.textContent?.trim();
  return title || 'window';
}
