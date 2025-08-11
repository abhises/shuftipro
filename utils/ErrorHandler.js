export default class ErrorHandler {
  // Store the error records
  static errors = [];

  /**
  Adds an error message and optional data to the error list
  @since 1.0
  @version 1.0
  @author Linden May
  @param {string} message - The error message to record
  @param {any} [data=null] - Optional additional error data
  @returns {void} No return value
  */
  static add_error(message, data = null) {
    // Add the error message and data to the errors array
    this.errors.push({ message, data });
  }

  /**
  Checks if any errors have been recorded
  @since 1.0
  @version 1.0
  @author Linden May
  @returns {boolean} True if errors array is not empty
  */
  static has_errors() {
    // Check if the errors array has any items
    return this.errors.length > 0;
  }

  /**
  Retrieves all recorded error messages
  @since 1.0
  @version 1.0
  @author Linden May
  @returns {Array<object>} Array of error objects
  */
  static get_all_errors() {
    // Return all error objects
    return this.errors;
  }

  /**
  Clears all recorded errors
  @since 1.0
  @version 1.0
  @author Linden May
  @returns {void} No return value
  */
  static clear() {
    // Clear the errors array
    this.errors = [];
  }
}

// Export the ErrorHandler class
