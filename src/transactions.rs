use std::error::Error;
use log::{debug, error};
use millegrilles_common_rust::bson::{Bson, doc};
use millegrilles_common_rust::certificats::{ValidateurX509, VerificateurPermissions};
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::verifier_reponse_ok;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::formatteur_messages::MessageMilleGrille;
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::middleware::sauvegarder_traiter_transaction;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, convertir_to_bson, convertir_to_bson_array, MongoDao};
use millegrilles_common_rust::mongodb::options::{FindOneAndUpdateOptions, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::recepteur_messages::MessageValideAction;
use millegrilles_common_rust::serde_json::json;
use millegrilles_common_rust::transactions::Transaction;
use millegrilles_common_rust::verificateur::VerificateurMessage;

use crate::common::*;
use crate::constantes::*;
use crate::gestionnaire::GestionnaireLanding;

pub async fn aiguillage_transaction<M, T>(gestionnaire: &GestionnaireLanding, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    let action = match transaction.get_routage().action.as_ref() {
        Some(inner) => inner.as_str(),
        None => Err(format!("transactions.aiguillage_transaction: Transaction {} n'a pas de type d'action", transaction.get_uuid_transaction()))?
    };

    match action {
        TRANSACTION_CREER_NOUVELLE_APPLICATION => transaction_creer_nouvelle_application(gestionnaire, middleware, transaction).await,
        TRANSACTION_SAUVEGARDER_APPLICATION => transaction_sauvegarder_application(gestionnaire, middleware, transaction).await,
        _ => Err(format!("transactions.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), action)),
    }
}

pub async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireLanding)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    // Autorisation
    match m.action.as_str() {
        // 4.secure - doivent etre validees par une commande
        TRANSACTION_CREER_NOUVELLE_APPLICATION => {
            match m.verifier_exchanges(vec![Securite::L4Secure]) {
                true => Ok(()),
                false => Err(format!("transactions.consommer_transaction: Message autorisation invalide (pas 4.secure)"))
            }?;
        },
        _ => Err(format!("transactions.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }

    Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
}

async fn transaction_creer_nouvelle_application<M,T>(gestionnaire: &GestionnaireLanding, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_sauvegarder_categorie_usager Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => match e.get_user_id()? {
            Some(inner) => inner.to_owned(),
            None => Err(format!("transactions.transaction_sauvegarder_categorie_usager User_id absent du certificat (cert)"))?
        },
        None => Err(format!("transactions.transaction_sauvegarder_categorie_usager User_id absent du certificat (enveloppe)"))?
    };

    let filtre = doc! { CHAMP_APPLICATION_ID: &uuid_transaction };

    let ops = doc! {
        "$set": {
            "actif": false,
        },
        "$setOnInsert": {
            CHAMP_APPLICATION_ID: &uuid_transaction,
            CHAMP_USER_ID: &user_id,
            CHAMP_CREATION: Utc::now()
        },
        "$currentDate": {
            CHAMP_MODIFICATION: true,
        }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_APPLICATIONS)?;
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();
    if let Err(e) = collection.update_one(filtre, ops, options).await {
        Err(format!("Erreur insertion/update application_id {} : {:?}", uuid_transaction, e))?
    }

    let reponse = json!({ "ok": true, "application_id": &uuid_transaction });

    match middleware.formatter_reponse(reponse, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur preparation confirmat envoi message {} : {:?}", uuid_transaction, e))
    }
}

async fn transaction_sauvegarder_application<M,T>(gestionnaire: &GestionnaireLanding, middleware: &M, transaction: T)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_sauvegarder_categorie_usager Consommer transaction : {:?}", &transaction);
    let uuid_transaction = transaction.get_uuid_transaction().to_owned();
    let user_id = match transaction.get_enveloppe_certificat() {
        Some(e) => match e.get_user_id()? {
            Some(inner) => inner.to_owned(),
            None => Err(format!("transactions.transaction_sauvegarder_categorie_usager User_id absent du certificat (cert)"))?
        },
        None => Err(format!("transactions.transaction_sauvegarder_categorie_usager User_id absent du certificat (enveloppe)"))?
    };

    let transaction_application: TransactionSauvegarderApplication = match transaction.convertir() {
        Ok(t) => t,
        Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur conversion transaction : {:?}", e))?
    };

    let filtre = doc! { CHAMP_APPLICATION_ID: &transaction_application.application_id, CHAMP_USER_ID: &user_id };

    let actif = match transaction_application.actif.as_ref() {
        Some(b) => b.to_owned(),
        None => false
    };

    let ops = doc! {
        "$set": {
            "nom": transaction_application.nom.as_ref(),
            "actif": actif,
        },
        "$setOnInsert": {
            CHAMP_APPLICATION_ID: &uuid_transaction,
            CHAMP_USER_ID: &user_id,
            CHAMP_CREATION: Utc::now()
        },
        "$currentDate": {
            CHAMP_MODIFICATION: true,
        }
    };

    let collection = middleware.get_collection(NOM_COLLECTION_APPLICATIONS)?;
    let options = UpdateOptions::builder()
        .upsert(true)
        .build();
    if let Err(e) = collection.update_one(filtre, ops, options).await {
        Err(format!("Erreur insertion/update application_id {} : {:?}", uuid_transaction, e))?
    }

    let reponse = json!({ "ok": true, "application_id": &uuid_transaction });

    match middleware.formatter_reponse(reponse, None) {
        Ok(r) => Ok(Some(r)),
        Err(e) => Err(format!("transactions.transaction_sauvegarder_categorie_usager Erreur preparation confirmat envoi message {} : {:?}", uuid_transaction, e))
    }
}

// async fn transaction_sauvegarder_groupe_usager<M,T>(gestionnaire: &GestionnaireLanding, middleware: &M, transaction: T)
//     -> Result<Option<MessageMilleGrille>, String>
//     where
//         M: GenerateurMessages + MongoDao,
//         T: Transaction
// {
//     debug!("transaction_sauvegarder_groupe_usager Consommer transaction : {:?}", &transaction);
//     let uuid_transaction = transaction.get_uuid_transaction().to_owned();
//     let user_id = match transaction.get_enveloppe_certificat() {
//         Some(e) => match e.get_user_id()? {
//             Some(inner) => inner.to_owned(),
//             None => Err(format!("transactions.transaction_sauvegarder_groupe_usager User_id absent du certificat (cert)"))?
//         },
//         None => Err(format!("transactions.transaction_sauvegarder_groupe_usager User_id absent du certificat (enveloppe)"))?
//     };
//
//     let transaction_groupe: TransactionSauvegarderGroupeUsager = match transaction.convertir() {
//         Ok(t) => t,
//         Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur conversion transaction : {:?}", e))?
//     };
//
//     if middleware.get_mode_regeneration() == false {
//         if let Some(maitrecles) = transaction_groupe.commande_maitredescles {
//             debug!("transaction_sauvegarder_groupe_usager Emettre commande pour cle de groupe");
//             let routage = RoutageMessageAction::builder(DOMAINE_NOM_MAITREDESCLES, COMMANDE_SAUVEGARDER_CLE)
//                 .exchanges(vec![Securite::L4Secure])
//                 .build();
//             if let Some(reponse) = middleware.transmettre_commande(routage, &maitrecles, true).await? {
//                 debug!("Reponse sauvegarde cle : {:?}", reponse);
//                 if !verifier_reponse_ok(&reponse) {
//                     Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur sauvegarde cle"))?
//                 }
//             } else {
//                 Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur sauvegarde cle - timeout/erreur"))?
//             }
//         }
//     }
//
//     let groupe_id = if let Some(groupe_id) = transaction_groupe.groupe_id {
//         groupe_id
//     } else {
//         uuid_transaction.clone()
//     };
//
//     let set_on_insert = doc! {
//         "groupe_id": &groupe_id,
//         "categorie_id": &transaction_groupe.categorie_id,
//         "user_id": &user_id,
//         CHAMP_CREATION: Utc::now(),
//     };
//
//     let bson_format: Bson = transaction_groupe.format.into();
//     let set_ops = doc! {
//         "data_chiffre": transaction_groupe.data_chiffre,
//         "format": bson_format,
//         "header": transaction_groupe.header,
//         "ref_hachage_bytes": transaction_groupe.ref_hachage_bytes,
//     };
//
//     // Remplacer la version la plus recente
//     let document_groupe = {
//         let filtre = doc! {
//             "groupe_id": &groupe_id,
//             "user_id": &user_id,
//         };
//
//         let ops = doc! {
//             "$set": &set_ops,
//             "$setOnInsert": &set_on_insert,
//             "$currentDate": {CHAMP_MODIFICATION: true},
//         };
//
//         let collection = middleware.get_collection(NOM_COLLECTION_GROUPES_USAGERS)?;
//         let options = FindOneAndUpdateOptions::builder()
//             .upsert(true)
//             .return_document(ReturnDocument::After)
//             .build();
//         let resultat: TransactionSauvegarderGroupeUsager = match collection.find_one_and_update(filtre, ops, options).await {
//             Ok(inner) => match inner {
//                 Some(inner) => match convertir_bson_deserializable(inner) {
//                     Ok(inner) => inner,
//                     Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur insert/maj groupe usager (mapping) : {:?}", e))?
//                 },
//                 None => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur insert/maj groupe usager (None)"))?
//             },
//             Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur insert/maj groupe usager (exec) : {:?}", e))?
//         };
//
//         resultat
//     };
//
//     // Emettre evenement maj
//     let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SAUVEGARDER_GROUPE_USAGER)
//         .exchanges(vec![Securite::L2Prive])
//         .partition(user_id)
//         .build();
//     middleware.emettre_evenement(routage, &document_groupe).await?;
//
//     let reponse = json!({ "ok": true });
//     match middleware.formatter_reponse(reponse, None) {
//         Ok(r) => Ok(Some(r)),
//         Err(e) => Err(format!("transactions.transaction_sauvegarder_groupe_usager Erreur preparation confirmat envoi message {} : {:?}", uuid_transaction, e))
//     }
//
// }
//
// async fn transaction_sauvegarder_document<M,T>(gestionnaire: &GestionnaireLanding, middleware: &M, transaction: T)
//     -> Result<Option<MessageMilleGrille>, String>
//     where
//         M: GenerateurMessages + MongoDao,
//         T: Transaction
// {
//     debug!("transaction_sauvegarder_document Consommer transaction : {:?}", &transaction);
//     let uuid_transaction = transaction.get_uuid_transaction().to_owned();
//     let user_id = match transaction.get_enveloppe_certificat() {
//         Some(e) => match e.get_user_id()? {
//             Some(inner) => inner.to_owned(),
//             None => Err(format!("transactions.transaction_sauvegarder_document User_id absent du certificat (cert)"))?
//         },
//         None => Err(format!("transactions.transaction_sauvegarder_document User_id absent du certificat (enveloppe)"))?
//     };
//
//     let transaction_doc: TransactionSauvegarderDocument = match transaction.convertir() {
//         Ok(t) => t,
//         Err(e) => Err(format!("transactions.transaction_sauvegarder_document Erreur conversion transaction : {:?}", e))?
//     };
//
//     let doc_id = if let Some(doc_id) = transaction_doc.doc_id {
//         doc_id
//     } else {
//         uuid_transaction.clone()
//     };
//
//     let set_on_insert = doc! {
//         "doc_id": &doc_id,
//         "groupe_id": &transaction_doc.groupe_id,
//         "user_id": &user_id,
//         CHAMP_CREATION: Utc::now(),
//     };
//
//     let bson_format: Bson = transaction_doc.format.into();
//     let set_ops = doc! {
//         "categorie_version": transaction_doc.categorie_version,
//         "data_chiffre": transaction_doc.data_chiffre,
//         "format": bson_format,
//         "header": transaction_doc.header,
//     };
//
//     // Remplacer la version la plus recente
//     let document_doc = {
//         let filtre = doc! {
//             "doc_id": &doc_id,
//             "user_id": &user_id,
//         };
//
//         let ops = doc! {
//             "$set": &set_ops,
//             "$setOnInsert": &set_on_insert,
//             "$currentDate": {CHAMP_MODIFICATION: true},
//         };
//
//         let collection = middleware.get_collection(NOM_COLLECTION_DOCUMENTS_USAGERS)?;
//         let options = FindOneAndUpdateOptions::builder()
//             .upsert(true)
//             .return_document(ReturnDocument::After)
//             .build();
//         let resultat: DocDocument = match collection.find_one_and_update(filtre, ops, options).await {
//             Ok(inner) => match inner {
//                 Some(inner) => match convertir_bson_deserializable(inner) {
//                     Ok(inner) => inner,
//                     Err(e) => Err(format!("transactions.transaction_sauvegarder_document Erreur insert/maj groupe usager (mapping) : {:?}", e))?
//                 },
//                 None => Err(format!("transactions.transaction_sauvegarder_document Erreur insert/maj groupe usager (None)"))?
//             },
//             Err(e) => Err(format!("transactions.transaction_sauvegarder_document Erreur insert/maj groupe usager (exec) : {:?}", e))?
//         };
//
//         resultat
//     };
//
//     // Emettre evenement maj
//     let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_SAUVEGARDER_DOCUMENT)
//         .exchanges(vec![Securite::L2Prive])
//         .partition(user_id)
//         .build();
//     middleware.emettre_evenement(routage, &document_doc).await?;
//
//     let reponse = json!({ "ok": true });
//     match middleware.formatter_reponse(reponse, None) {
//         Ok(r) => Ok(Some(r)),
//         Err(e) => Err(format!("transactions.transaction_sauvegarder_document Erreur preparation confirmat envoi message {} : {:?}", uuid_transaction, e))
//     }
//
// }
