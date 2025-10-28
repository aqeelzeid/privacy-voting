/**
 * Represents a standardized error structure with a type and message.
 */
export type ErrorType = {
    type: string;    // The category or type of error
    message: string; // Human-readable error description
}

/**`
 * A discriminated union type representing either a successful result with a value
 * or a failed result with an error.
 * 
 * @template R - The type of the success value
 * @template E - The type of the error value
 */
export type Result<R, E> = { ok: true; value: R } | { ok: false; error: E };

/**
 * Creates a successful Result containing a value.
 * 
 * @template R - The type of the success value
 * @param value - The success value to wrap
 * @returns A Result object indicating success with the provided value
 * 
 * @example
 * const result = ok(42);
 * if (result.ok) console.log(result.value); // 42
 */
export function ok<R>(value: R): Result<R, never> {
  return { ok: true, value };
}

/**
 * Creates a failed Result containing an error.
 * 
 * @template E - The type of the error value
 * @param error - The error value to wrap
 * @returns A Result object indicating failure with the provided error
 * 
 * @example
 * const result = err({ type: 'ValidationError', message: 'Invalid input' });
 * if (!result.ok) console.log(result.error);
 */
export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

/**
 * A class that wraps errors with additional context information, allowing for
 * error chaining and detailed error tracking through the application.
 * 
 * @template E - The type of error being wrapped, must extend ErrorType
 */
export class WrappedError<E extends ErrorType> {
  /**
   * Creates a new wrapped error instance.
   * 
   * @param message - A description of what went wrong
   * @param cause - The original error or another wrapped error that caused this error
   * @param context - Where in the code this error occurred (e.g., function name, module)
   */
  constructor(
    public message: string,
    public cause: E | WrappedError<E>,
    public context: string
  ) {}

  /**
   * Converts the wrapped error into a human-readable string format,
   * including the full error chain.
   * 
   * @returns A formatted string representing the complete error chain
   * 
   * @example
   * const error = new WrappedError(
   *   "Failed to process user input",
   *   { type: "ValidationError", message: "Invalid email" },
   *   "UserService.create"
   * );
   * console.log(error.toString());
   * // Output: Failed to process user input at UserService.create:
   * //     ValidationError: Invalid email
   */
  toString(): string {
    // If the cause is another WrappedError, recursively get its string representation
    const causeMessage = this.cause instanceof WrappedError
      ? this.cause.toString()
      : `${this.cause.type}: ${this.cause.message}`;
    
    return `${this.message} at ${this.context}:\n    ${causeMessage}`;
  }
}