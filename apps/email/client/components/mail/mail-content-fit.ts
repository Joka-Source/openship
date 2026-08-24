export interface MailContentFit {
  layoutWidth: number | null;
  scale: number;
}

export function calculateMailContentFit(
  availableWidth: number,
  contentWidth: number,
): MailContentFit {
  if (
    !Number.isFinite(availableWidth) ||
    !Number.isFinite(contentWidth) ||
    availableWidth <= 0 ||
    contentWidth <= 0 ||
    contentWidth <= availableWidth
  ) {
    return { layoutWidth: null, scale: 1 };
  }

  return {
    layoutWidth: contentWidth,
    scale: availableWidth / contentWidth,
  };
}

export function fitMailContentToWidth(host: HTMLElement, content: HTMLElement): void {
  content.style.width = '100%';
  content.style.zoom = '1';

  const hostStyle = window.getComputedStyle(host);
  const horizontalPadding =
    Number.parseFloat(hostStyle.paddingLeft) + Number.parseFloat(hostStyle.paddingRight);
  const availableWidth = Math.max(0, host.clientWidth - horizontalPadding);
  const contentWidth = Math.max(availableWidth, content.scrollWidth);
  const fit = calculateMailContentFit(availableWidth, contentWidth);

  if (fit.layoutWidth !== null) {
    content.style.width = `${fit.layoutWidth}px`;
    content.style.zoom = String(fit.scale);
  }
}
