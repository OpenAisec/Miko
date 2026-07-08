/**
 * Command semantics configuration for interpreting exit codes in different contexts.
 *
 * Many commands use exit codes to convey information other than just success/failure.
 * For example, grep returns 1 when no matches are found, which is not an error condition.
 */

import { splitCommand_DEPRECATED } from '../../utils/bash/commands.js'

export type CommandSemantic = (
  exitCode: number,
  stdout: string,
  stderr: string,
) => {
  isError: boolean
  message?: string
}

/**
 * Exit code meanings for common scenarios
 */
const EXIT_CODE_MEANINGS: Record<number, string> = {
  1: 'General error',
  2: 'Misuse of shell command or file not found',
  126: 'Command cannot execute (permission problem)',
  127: 'Command not found',
  128: 'Invalid argument to exit',
  130: 'Script terminated by Ctrl+C',
  255: 'Exit status out of range',
}

/**
 * Default semantic: treat only 0 as success, everything else as error
 */
const DEFAULT_SEMANTIC: CommandSemantic = (exitCode, _stdout, _stderr) => {
  if (exitCode === 0) {
    return { isError: false }
  }

  // Get meaningful description for common exit codes
  const meaning = EXIT_CODE_MEANINGS[exitCode]
  const message = meaning
    ? `Command failed with exit code ${exitCode} (${meaning})`
    : `Command failed with exit code ${exitCode}`

  return { isError: true, message }
}

/**
 * Command-specific semantics
 */
const COMMAND_SEMANTICS: Map<string, CommandSemantic> = new Map([
  // grep: 0=matches found, 1=no matches, 2+=error
  [
    'grep',
    (exitCode, _stdout, _stderr) => ({
      isError: exitCode >= 2,
      message: exitCode === 1 ? 'No matches found' : undefined,
    }),
  ],

  // ripgrep has same semantics as grep
  [
    'rg',
    (exitCode, _stdout, _stderr) => ({
      isError: exitCode >= 2,
      message: exitCode === 1 ? 'No matches found' : undefined,
    }),
  ],

  // find: 0=success, 1=partial success (some dirs inaccessible), 2+=error
  [
    'find',
    (exitCode, _stdout, _stderr) => ({
      isError: exitCode >= 2,
      message:
        exitCode === 1 ? 'Some directories were inaccessible' : undefined,
    }),
  ],

  // diff: 0=no differences, 1=differences found, 2+=error
  [
    'diff',
    (exitCode, _stdout, _stderr) => ({
      isError: exitCode >= 2,
      message: exitCode === 1 ? 'Files differ' : undefined,
    }),
  ],

  // test/[: 0=condition true, 1=condition false, 2+=error
  [
    'test',
    (exitCode, _stdout, _stderr) => ({
      isError: exitCode >= 2,
      message: exitCode === 1 ? 'Condition is false' : undefined,
    }),
  ],

  // [ is an alias for test
  [
    '[',
    (exitCode, _stdout, _stderr) => ({
      isError: exitCode >= 2,
      message: exitCode === 1 ? 'Condition is false' : undefined,
    }),
  ],

  // wc, head, tail, cat, etc.: these typically only fail on real errors
  // so we use default semantics
])

/**
 * Get the semantic interpretation for a command
 */
function getCommandSemantic(command: string): CommandSemantic {
  // Extract the base command (first word, handling pipes)
  const baseCommand = heuristicallyExtractBaseCommand(command)
  const semantic = COMMAND_SEMANTICS.get(baseCommand)
  return semantic !== undefined ? semantic : DEFAULT_SEMANTIC
}

/**
 * Extract just the command name (first word) from a single command string.
 */
function extractBaseCommand(command: string): string {
  return command.trim().split(/\s+/)[0] || ''
}

/**
 * Extract the primary command from a complex command line;
 * May get it super wrong - don't depend on this for security
 */
function heuristicallyExtractBaseCommand(command: string): string {
  const segments = splitCommand_DEPRECATED(command)

  // Take the last command as that's what determines the exit code
  const lastCommand = segments[segments.length - 1] || command

  return extractBaseCommand(lastCommand)
}

/**
 * Interpret command result based on semantic rules
 */
export function interpretCommandResult(
  command: string,
  exitCode: number,
  stdout: string,
  stderr: string,
): {
  isError: boolean
  message?: string
} {
  const semantic = getCommandSemantic(command)
  const result = semantic(exitCode, stdout, stderr)

  return {
    isError: result.isError,
    message: result.message,
  }
}
