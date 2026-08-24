import { describe, expect, it } from 'bun:test';

import { calculateMailContentFit } from './mail-content-fit';

describe('mail content width fitting', () => {
  it('scales a fixed-width message to the available reading pane', () => {
    expect(calculateMailContentFit(608, 1600)).toEqual({
      layoutWidth: 1600,
      scale: 0.38,
    });
  });

  it('leaves a message that already fits at its authored size', () => {
    expect(calculateMailContentFit(608, 480)).toEqual({
      layoutWidth: null,
      scale: 1,
    });
  });

  it('fails open when layout measurements are not usable yet', () => {
    expect(calculateMailContentFit(0, 1600)).toEqual({
      layoutWidth: null,
      scale: 1,
    });
  });
});
