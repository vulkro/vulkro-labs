//! Lookalike / confusable detection: is this name a homoglyph or a one-edit
//! typosquat of a very popular package?
//!
//! Pure commodity string math (Unicode homoglyph folding + Optimal String
//! Alignment edit distance) over an embedded list of high-value package names.
//! No network, no closed logic. This closes the gap where an aged,
//! download-bootstrapped slopsquat passes existence + OSV + reputation checks.

use vulkro_feeds::Ecosystem;

/// The most-installed / most-typosquatted npm packages. A name that is a
/// homoglyph or a single edit from one of these, but is not itself on the list,
/// is a lookalike.
const NPM_TOP: &[&str] = &[
    "express", "react", "react-dom", "lodash", "axios", "chalk", "commander", "debug", "request",
    "async", "moment", "bluebird", "underscore", "vue", "webpack", "typescript", "jest", "eslint",
    "prettier", "dotenv", "body-parser", "cors", "mongoose", "redux", "next", "classnames", "uuid",
    "yargs", "glob", "rimraf", "semver", "fs-extra", "node-fetch", "ws", "jsonwebtoken", "bcrypt",
    "passport", "nodemon", "concurrently", "cross-env", "husky", "styled-components", "tailwindcss",
    "vite", "rollup", "esbuild", "zod", "dayjs", "ramda", "immer", "formik", "yup", "ethers",
    "puppeteer", "playwright", "cheerio", "sharp", "multer", "winston", "pino", "ioredis", "pg",
    "mysql2", "sequelize", "prisma", "graphql", "fastify", "koa", "electron", "three", "d3",
    "stripe", "firebase", "openai", "langchain", "discord.js", "nanoid", "qs", "minimist", "colors",
    "inquirer", "ora", "execa", "chokidar", "postcss", "autoprefixer", "sass",
];

/// The most-installed / most-typosquatted PyPI packages.
const PYPI_TOP: &[&str] = &[
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "fastapi", "setuptools", "boto3",
    "botocore", "scipy", "matplotlib", "pillow", "sqlalchemy", "pytest", "click", "jinja2",
    "werkzeug", "pyyaml", "cryptography", "certifi", "idna", "six", "python-dateutil", "pytz",
    "aiohttp", "httpx", "beautifulsoup4", "lxml", "scrapy", "selenium", "tensorflow", "torch",
    "scikit-learn", "transformers", "openai", "langchain", "pydantic", "uvicorn", "gunicorn",
    "celery", "redis", "psycopg2", "pymongo", "tqdm", "rich", "typer", "poetry", "black", "flake8",
    "mypy", "isort", "virtualenv", "pipenv", "paramiko", "opencv-python", "seaborn", "plotly",
    "streamlit", "gradio", "colorama",
];

/// The most-installed / most-typosquatted crates.io crates.
const CRATES_TOP: &[&str] = &[
    "serde", "serde_json", "tokio", "clap", "anyhow", "thiserror", "rand", "log", "regex",
    "reqwest", "syn", "quote", "proc-macro2", "libc", "futures", "bytes", "chrono", "itertools",
    "hyper", "tracing", "async-trait", "lazy_static", "once_cell", "parking_lot", "rayon", "toml",
    "base64", "uuid", "semver", "url", "time", "tempfile", "walkdir", "dirs", "which", "indicatif",
    "console", "crossterm", "ratatui", "axum", "actix-web", "diesel", "sqlx", "sea-orm", "tonic",
    "prost", "bindgen", "num", "ndarray", "nalgebra", "image", "winit", "wgpu", "bevy", "egui",
];

/// The popular package `name` mimics, or `None`. Skips names that are
/// themselves on the top list (a known package is not a lookalike of another).
pub fn detect(name: &str, ecosystem: Ecosystem) -> Option<String> {
    let list = match ecosystem {
        Ecosystem::Npm => NPM_TOP,
        Ecosystem::PyPI => PYPI_TOP,
        Ecosystem::Crates => CRATES_TOP,
    };
    let lower = name.to_lowercase();
    if list.contains(&lower.as_str()) {
        return None;
    }

    // 1. Homoglyph confusable: identical skeletons but different raw names
    // (Cyrillic а vs Latin a, fullwidth chars, and the like).
    let name_skeleton = skeleton(&lower);
    for &top in list {
        if lower != top && name_skeleton == skeleton(top) {
            return Some(top.to_string());
        }
    }

    // 2. One-edit typo (Optimal String Alignment distance 1: a substitution,
    // insertion, deletion, or adjacent transposition). Very short names have
    // dense one-edit neighborhoods, so require at least four characters.
    if lower.chars().count() >= 4 {
        for &top in list {
            let len_gap = (top.chars().count() as isize - lower.chars().count() as isize).abs();
            if len_gap <= 1 && osa_distance(&lower, top) == 1 {
                return Some(top.to_string());
            }
        }
    }
    None
}

/// Fold a string to its confusable skeleton: map common Cyrillic / Greek /
/// fullwidth homoglyphs to their Latin/ASCII lookalike.
fn skeleton(s: &str) -> String {
    s.chars().map(fold_char).collect()
}

fn fold_char(c: char) -> char {
    let u = c as u32;
    // Fullwidth ASCII block maps directly onto ASCII.
    if (0xFF01..=0xFF5E).contains(&u) {
        return char::from_u32(u - 0xFEE0).unwrap_or(c);
    }
    match c {
        // Cyrillic lowercase homoglyphs.
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x', 'у' => 'y',
        'ѕ' => 's', 'і' => 'i', 'ј' => 'j', 'ԁ' => 'd', 'һ' => 'h', 'ӏ' => 'l', 'ԛ' => 'q',
        'ԝ' => 'w', 'ո' => 'n',
        // Greek lowercase homoglyphs.
        'ο' => 'o', 'α' => 'a', 'ρ' => 'p', 'ε' => 'e', 'ι' => 'i', 'ν' => 'v', 'τ' => 't',
        'κ' => 'k', 'μ' => 'u', 'γ' => 'y', 'χ' => 'x',
        _ => c,
    }
}

/// Optimal String Alignment (Damerau-Levenshtein restricted to adjacent
/// transpositions) distance between two strings.
fn osa_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n == 0 {
        return m;
    }
    if m == 0 {
        return n;
    }
    let mut prev2 = vec![0usize; m + 1];
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];
    for i in 1..=n {
        curr[0] = i;
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut val = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                val = val.min(prev2[j - 2] + 1);
            }
            curr[j] = val;
        }
        std::mem::swap(&mut prev2, &mut prev);
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_edit_typo_is_a_lookalike() {
        assert_eq!(detect("expresss", Ecosystem::Npm).as_deref(), Some("express"));
        assert_eq!(detect("reqeusts", Ecosystem::PyPI).as_deref(), Some("requests"));
        assert_eq!(detect("tokoi", Ecosystem::Crates).as_deref(), Some("tokio"));
    }

    #[test]
    fn homoglyph_is_a_lookalike() {
        // Cyrillic 'е' in the middle of "requests".
        assert_eq!(detect("r\u{435}quests", Ecosystem::PyPI).as_deref(), Some("requests"));
    }

    #[test]
    fn separator_swap_is_a_lookalike() {
        // A single edit: "reactdom" is one deletion from "react-dom".
        assert_eq!(detect("reactdom", Ecosystem::Npm).as_deref(), Some("react-dom"));
    }

    #[test]
    fn the_real_package_is_not_a_lookalike() {
        assert_eq!(detect("express", Ecosystem::Npm), None);
        assert_eq!(detect("requests", Ecosystem::PyPI), None);
    }

    #[test]
    fn unrelated_name_is_not_a_lookalike() {
        assert_eq!(detect("my-cool-internal-app", Ecosystem::Npm), None);
    }

    #[test]
    fn short_names_are_not_flagged() {
        // "vue" is three chars; its dense one-edit neighborhood is too noisy.
        assert_eq!(detect("vae", Ecosystem::Npm), None);
    }

    #[test]
    fn osa_counts_transposition_as_one() {
        assert_eq!(osa_distance("axios", "aixos"), 1);
        assert_eq!(osa_distance("lodash", "lodash"), 0);
    }
}
