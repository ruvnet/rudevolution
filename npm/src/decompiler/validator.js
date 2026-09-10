/**
 * validator.js - Operational validation for reconstructed code.
 *
 * Checks static properties of a reconstruction without executing input:
 *   - Syntax validity (parseable without errors)
 *   - String literal preservation (all strings intact)
 *   - Class hierarchy preservation (same extends chains)
 *   - Export preservation (same exports)
 *   - Byte identity; changed programs have unverified behavior
 */

'use strict';

// Validation never executes input code.

/**
 * Check static preservation signals; these do not prove semantic equivalence.
 *
 * @param {string} originalSource - the minified/beautified original
 * @param {string} reconstructedSource - the reconstructed version
 * @param {object} [options]
 * @param {boolean} [options.checkSyntax=true]
 * @param {boolean} [options.checkStrings=true]
 * @param {boolean} [options.checkClasses=true]
 * @param {boolean} [options.checkFunctions=true]
 * @returns {{syntaxValid: boolean, exportsMatch: boolean, stringsPreserved: boolean, classesMatch: boolean, functionallyEquivalent: boolean|null, issues: string[]}}
 */
function validateReconstruction(originalSource, reconstructedSource, options = {}) {
  const {
    checkSyntax = true,
    checkStrings = true,
    checkClasses = true,
    checkFunctions = true,
  } = options;

  const issues = [];
  let syntaxValid = true;
  let stringsPreserved = true;
  let classesMatch = true;
  let exportsMatch = true;
  let functionallyEquivalent = true;

  // 1. Syntax check
  if (checkSyntax) {
    const syntaxResult = checkSyntaxValidity(reconstructedSource);
    syntaxValid = syntaxResult.valid;
    if (!syntaxValid) {
      issues.push(`Syntax error: ${syntaxResult.error}`);
      // If syntax is broken, further checks are unreliable
      return {
        syntaxValid,
        exportsMatch: false,
        stringsPreserved: false,
        classesMatch: false,
        functionallyEquivalent: false,
        issues,
      };
    }
  }

  // 2. String literal preservation
  if (checkStrings) {
    const result = checkStringPreservation(originalSource, reconstructedSource);
    stringsPreserved = result.preserved;
    for (const missing of result.missing) {
      issues.push(`Missing string literal: "${missing}"`);
    }
  }

  // 3. Class hierarchy preservation
  if (checkClasses) {
    const result = checkClassHierarchy(originalSource, reconstructedSource);
    classesMatch = result.match;
    for (const issue of result.issues) {
      issues.push(issue);
    }
  }

  // 4. Export/function count check
  if (checkFunctions) {
    const result = checkFunctionPreservation(originalSource, reconstructedSource);
    exportsMatch = result.match;
    for (const issue of result.issues) {
      issues.push(issue);
    }
  }

  // 5. Static identity check; never run untrusted input
  if (syntaxValid) {
    const result = checkFunctionalEquivalence(
      originalSource,
      reconstructedSource,
    );
    functionallyEquivalent = result.equivalent;
    for (const issue of result.issues) {
      issues.push(issue);
    }
  }

  return {
    syntaxValid,
    exportsMatch,
    stringsPreserved,
    classesMatch,
    functionallyEquivalent,
    issues,
  };
}

/**
 * Check if source code is syntactically valid JavaScript.
 *
 * @param {string} source
 * @returns {{valid: boolean, error: string|null}}
 */
function checkSyntaxValidity(source) {
  try {
    // Use Function constructor for syntax check (does not execute)
    new Function(source);
    return { valid: true, error: null };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Check that all string literals from the original appear in the reconstruction.
 * Identifiers may change, but string values must be preserved.
 *
 * @param {string} original
 * @param {string} reconstructed
 * @returns {{preserved: boolean, missing: string[], total: number}}
 */
function checkStringPreservation(original, reconstructed) {
  const origStrings = extractStringLiterals(original);
  const reconStrings = new Set(extractStringLiterals(reconstructed));

  const missing = [];
  for (const s of origStrings) {
    // Skip very short strings and common noise
    if (s.length < 2) continue;
    if (!reconStrings.has(s)) {
      missing.push(s);
    }
  }

  return {
    preserved: missing.length === 0,
    missing: missing.slice(0, 20), // Cap at 20 for reporting
    total: origStrings.length,
  };
}

/**
 * Extract all string literals from source code.
 *
 * @param {string} source
 * @returns {string[]}
 */
function extractStringLiterals(source) {
  const strings = [];

  // Match double-quoted strings
  const doubleQuoted = source.match(/"([^"\\]|\\.)*"/g) || [];
  for (const s of doubleQuoted) {
    strings.push(s.slice(1, -1));
  }

  // Match single-quoted strings
  const singleQuoted = source.match(/'([^'\\]|\\.)*'/g) || [];
  for (const s of singleQuoted) {
    strings.push(s.slice(1, -1));
  }

  return strings;
}

/**
 * Check that class hierarchies are preserved.
 * All "class X extends Y" pairs must appear in both versions.
 *
 * @param {string} original
 * @param {string} reconstructed
 * @returns {{match: boolean, issues: string[]}}
 */
function checkClassHierarchy(original, reconstructed) {
  const origClasses = extractClassHierarchy(original);
  const reconClasses = extractClassHierarchy(reconstructed);
  const issues = [];

  // Check that base classes are preserved (names may have changed)
  const origBases = new Set(origClasses.map((c) => c.base).filter(Boolean));
  const reconBases = new Set(reconClasses.map((c) => c.base).filter(Boolean));

  // Base class names (Error, EventEmitter, etc.) should be preserved
  for (const base of origBases) {
    if (!reconBases.has(base)) {
      // Check if it is a built-in that was renamed
      const builtIns = ['Error', 'TypeError', 'RangeError', 'EventEmitter', 'Stream', 'Buffer'];
      if (builtIns.includes(base)) {
        issues.push(`Base class "${base}" missing from reconstruction`);
      }
    }
  }

  // Same number of class declarations
  if (origClasses.length !== reconClasses.length) {
    issues.push(
      `Class count mismatch: original has ${origClasses.length}, reconstructed has ${reconClasses.length}`,
    );
  }

  return { match: issues.length === 0, issues };
}

/**
 * Extract class declarations and their inheritance.
 *
 * @param {string} source
 * @returns {Array<{name: string, base: string|null}>}
 */
function extractClassHierarchy(source) {
  const classes = [];
  const re = /class\s+(\w+)(?:\s+extends\s+(\w+))?/g;
  let match;
  while ((match = re.exec(source)) !== null) {
    classes.push({ name: match[1], base: match[2] || null });
  }
  return classes;
}

/**
 * Check that the number of functions/exports is preserved.
 *
 * @param {string} original
 * @param {string} reconstructed
 * @returns {{match: boolean, issues: string[]}}
 */
function checkFunctionPreservation(original, reconstructed) {
  const issues = [];

  const origFuncCount = (original.match(/function\s*[\w$]*\s*\(/g) || []).length;
  const reconFuncCount = (reconstructed.match(/function\s*[\w$]*\s*\(/g) || []).length;

  if (origFuncCount !== reconFuncCount) {
    issues.push(
      `Function count mismatch: original has ${origFuncCount}, reconstructed has ${reconFuncCount}`,
    );
  }

  const origArrowCount = (original.match(/=>/g) || []).length;
  const reconArrowCount = (reconstructed.match(/=>/g) || []).length;

  if (origArrowCount !== reconArrowCount) {
    issues.push(
      `Arrow function count mismatch: original has ${origArrowCount}, reconstructed has ${reconArrowCount}`,
    );
  }

  // Check module.exports / export counts
  const origExports = (original.match(/module\.exports|export\s+(default\s+)?/g) || []).length;
  const reconExports = (reconstructed.match(/module\.exports|export\s+(default\s+)?/g) || []).length;

  if (origExports !== reconExports) {
    issues.push(
      `Export count mismatch: original has ${origExports}, reconstructed has ${reconExports}`,
    );
  }

  return { match: issues.length === 0, issues };
}

/**
 * Only byte-identical sources can be certified here without execution.
 * Changed programs require external, OS-isolated differential tests.
 * null means unverified, never a passing behavioral check.
 */
function checkFunctionalEquivalence(original, reconstructed) {
  const identical = original === reconstructed;
  return {
    equivalent: identical ? true : null,
    status: identical ? 'identical' : 'unverified',
    issues: identical ? [] : ['Behavioral equivalence unverified: input execution is disabled'],
  };
}

module.exports = {
  validateReconstruction,
  checkSyntaxValidity,
  checkStringPreservation,
  checkClassHierarchy,
  checkFunctionPreservation,
  checkFunctionalEquivalence,
  extractStringLiterals,
};
