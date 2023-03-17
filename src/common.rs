use millegrilles_common_rust::chiffrage::FormatChiffrage;
use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::serde::{Deserialize, Serialize};

/// Commande/Transaction de sauvegarde d'une categorie usager.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionCreerNouvelleApplication {
}

/// Document de categorie pour un usager (collection mongo)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocApplication {
    pub user_id: String,
    pub application_id: String,
}

// /// Champ d'une categorie
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct ChampCategorie {
//     pub nom_champ: String,
//     pub code_interne: String,
//     pub type_champ: String,
//     pub taille_maximum: Option<i32>,
//     pub requis: Option<bool>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionSauvegarderGroupeUsager {
//     pub groupe_id: Option<String>,
//     pub categorie_id: String,
//     pub data_chiffre: String,
//     pub format: FormatChiffrage,
//     pub header: String,
//     pub ref_hachage_bytes: String,
//     #[serde(rename="_commandeMaitrecles", skip_serializing_if = "Option::is_none")]
//     pub commande_maitredescles: Option<CommandeSauvegarderCle>,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DocGroupeUsager {
//     pub groupe_id: String,
//     pub categorie_id: String,
//     pub data_chiffre: String,
//     pub format: FormatChiffrage,
//     pub header: String,
//     pub ref_hachage_bytes: String,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct TransactionSauvegarderDocument {
//     pub doc_id: Option<String>,
//     pub groupe_id: String,
//     pub categorie_version: i32,
//     pub data_chiffre: String,
//     pub format: FormatChiffrage,
//     pub header: String,
// }
//
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct DocDocument {
//     pub doc_id: String,
//     pub groupe_id: String,
//     pub categorie_version: i32,
//     pub data_chiffre: String,
//     pub format: FormatChiffrage,
//     pub header: String,
// }
