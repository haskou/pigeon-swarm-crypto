import { InvalidCallMediaFrameError } from '../errors/InvalidCallMediaFrameError';

export class CallMediaReplayWindow {
  static readonly #SIZE = 1024;

  readonly #accepted = new Array<boolean>(CallMediaReplayWindow.#SIZE).fill(
    false,
  );

  #highest = -1;

  private slot(sequence: number): number {
    return sequence % CallMediaReplayWindow.#SIZE;
  }

  public accept(sequence: number): void {
    if (!this.admits(sequence)) throw new InvalidCallMediaFrameError();
    const advance = Math.min(
      sequence - this.#highest,
      CallMediaReplayWindow.#SIZE,
    );

    for (let step = 1; step <= advance; step += 1)
      this.#accepted[this.slot(this.#highest + step)] = false;
    this.#highest = Math.max(this.#highest, sequence);
    this.#accepted[this.slot(sequence)] = true;
  }

  public admits(sequence: number): boolean {
    return (
      sequence > this.#highest ||
      (sequence > this.#highest - CallMediaReplayWindow.#SIZE &&
        !this.#accepted[this.slot(sequence)])
    );
  }
}
