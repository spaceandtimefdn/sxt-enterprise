//! Parsing and rendering the column type names used in the HTTP API.

use arrow::datatypes::DataType;
use sqlparser::ast;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

/// A column type name that could not be parsed or is not supported.
#[derive(Debug, thiserror::Error)]
#[error("unsupported column type: {0}")]
pub struct UnsupportedType(String);

/// Parses a SQL type name (`"BIGINT"`, `"VARCHAR"`, ...) into an arrow [`DataType`].
///
/// # Errors
/// Fails if `name` is not valid SQL, or names a type this service does not support.
pub fn parse_column_type(name: &str) -> Result<DataType, UnsupportedType> {
    let unsupported = || UnsupportedType(name.to_owned());
    let parsed = Parser::new(&GenericDialect {})
        .try_with_sql(name)
        .and_then(|mut parser| parser.parse_data_type())
        .map_err(|_err| unsupported())?;
    match parsed {
        ast::DataType::Boolean | ast::DataType::Bool => Ok(DataType::Boolean),
        ast::DataType::TinyInt(_) => Ok(DataType::Int8),
        ast::DataType::SmallInt(_) => Ok(DataType::Int16),
        ast::DataType::Int(_) | ast::DataType::Integer(_) => Ok(DataType::Int32),
        ast::DataType::BigInt(_) => Ok(DataType::Int64),
        ast::DataType::Varchar(_) | ast::DataType::Text | ast::DataType::String(_) => {
            Ok(DataType::Utf8)
        }
        _ => Err(unsupported()),
    }
}

/// The SQL type name a query against this column would use.
///
/// # Errors
/// Fails if `data_type` is not one this service supports creating tables with.
pub fn column_type_name(data_type: &DataType) -> Result<&'static str, UnsupportedType> {
    match data_type {
        DataType::Boolean => Ok("BOOLEAN"),
        DataType::Int8 => Ok("TINYINT"),
        DataType::Int16 => Ok("SMALLINT"),
        DataType::Int32 => Ok("INT"),
        DataType::Int64 => Ok("BIGINT"),
        DataType::Utf8 => Ok("VARCHAR"),
        other => Err(UnsupportedType(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use arrow::datatypes::DataType;

    use super::{column_type_name, parse_column_type};

    #[test]
    fn every_supported_type_round_trips() {
        for name in ["BOOLEAN", "TINYINT", "SMALLINT", "INT", "BIGINT", "VARCHAR"] {
            let data_type = parse_column_type(name).unwrap();
            assert_eq!(column_type_name(&data_type).unwrap(), name);
        }
    }

    #[test]
    fn boolean_alias_parses() {
        assert_eq!(parse_column_type("BOOL").unwrap(), DataType::Boolean);
    }

    #[test]
    fn an_unknown_type_name_is_rejected() {
        let error = parse_column_type("not a type").unwrap_err();
        assert_eq!(error.to_string(), "unsupported column type: not a type");
    }

    #[test]
    fn unparseable_sql_is_rejected() {
        let error = parse_column_type("").unwrap_err();
        assert_eq!(error.to_string(), "unsupported column type: ");
    }

    #[test]
    fn an_unsupported_type_is_rejected() {
        let error = parse_column_type("FLOAT").unwrap_err();
        assert_eq!(error.to_string(), "unsupported column type: FLOAT");
    }

    #[test]
    fn an_unsupported_data_type_has_no_name() {
        let error = column_type_name(&DataType::Float32).unwrap_err();
        assert_eq!(error.to_string(), "unsupported column type: Float32");
    }
}
