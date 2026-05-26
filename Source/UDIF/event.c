#include "event.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

void udif_event_clear(udif_event_record* eventrec)
{
    UDIF_ASSERT(eventrec != NULL);

    if (eventrec != NULL)
    {
        qsc_memutils_secure_erase((uint8_t*)eventrec, sizeof(udif_event_record));
    }
}

udif_errors udif_event_create(udif_event_record* eventrec, udif_event_classes eventclass, udif_event_codes eventcode, const uint8_t* actorser, 
    const uint8_t* subjectser, const uint8_t* contextid, uint64_t timestamp, const uint8_t* payload, size_t payloadlen)
{
    UDIF_ASSERT(eventrec != NULL);

    qsc_keccak_state kstate = { 0 };
    udif_errors err;

    err = udif_error_none;

    if (eventrec == NULL || ((payload == NULL) && (payloadlen != 0U)))
    {
        err = udif_error_invalid_input;
    }
    else
    {
        udif_event_clear(eventrec);
        eventrec->eventclass = (uint8_t)eventclass;
        eventrec->eventcode = (uint16_t)eventcode;
        eventrec->timestamp = timestamp;
        eventrec->payloadlen = (uint64_t)payloadlen;

        if (actorser != NULL)
        {
            qsc_memutils_copy(eventrec->actorser, actorser, UDIF_SERIAL_NUMBER_SIZE);
        }

        if (subjectser != NULL)
        {
            qsc_memutils_copy(eventrec->subjectser, subjectser, UDIF_SERIAL_NUMBER_SIZE);
        }

        if (contextid != NULL)
        {
            qsc_memutils_copy(eventrec->contextid, contextid, UDIF_EVENT_CONTEXT_SIZE);
        }

        qsc_sha3_initialize(&kstate);
        qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)"UDIF:EVENT-PAYLOAD:V1", 21U);

        if (payloadlen > 0U)
        {
            qsc_sha3_update(&kstate, qsc_keccak_rate_256, payload, payloadlen);
        }

        qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, eventrec->payloaddigest);
    }

    return err;
}

udif_errors udif_event_serialize(uint8_t* output, size_t outlen, const udif_event_record* eventrec)
{
    UDIF_ASSERT(eventrec != NULL);
    UDIF_ASSERT(output != NULL);

    size_t pos;
    udif_errors err;

    err = udif_error_none;
    pos = 0U;

    if (output == NULL || eventrec == NULL || outlen != UDIF_EVENT_RECORD_SIZE)
    {
        err = udif_error_invalid_input;
    }
    else
    {
        output[pos] = eventrec->eventclass;
        pos += 1U;
        output[pos] = (uint8_t)eventrec->eventcode;
        output[pos + 1U] = (uint8_t)(eventrec->eventcode >> 8U);
        pos += 2U;
        qsc_memutils_copy(output + pos, eventrec->actorser, UDIF_SERIAL_NUMBER_SIZE);
        pos += UDIF_SERIAL_NUMBER_SIZE;
        qsc_memutils_copy(output + pos, eventrec->subjectser, UDIF_SERIAL_NUMBER_SIZE);
        pos += UDIF_SERIAL_NUMBER_SIZE;
        qsc_memutils_copy(output + pos, eventrec->contextid, UDIF_EVENT_CONTEXT_SIZE);
        pos += UDIF_EVENT_CONTEXT_SIZE;
        qsc_intutils_le64to8(output + pos, eventrec->timestamp);
        pos += 8U;
        qsc_memutils_copy(output + pos, eventrec->payloaddigest, UDIF_CRYPTO_HASH_SIZE);
        pos += UDIF_CRYPTO_HASH_SIZE;
        qsc_intutils_le64to8(output + pos, eventrec->payloadlen);
    }

    return err;
}

udif_errors udif_event_log(udif_mcel_manager* mgr, udif_ledger_type ledger, udif_event_codes eventcode, const uint8_t* actorser, const uint8_t* subjectser, 
    const uint8_t* contextid, uint64_t timestamp, const uint8_t* payload, size_t payloadlen)
{
    udif_event_record eventrec = { 0 };
    uint8_t enc[UDIF_EVENT_RECORD_SIZE] = { 0U };
    uint64_t outseq;
    udif_errors err;

    err = udif_error_none;

    if (mgr == NULL || ((payload == NULL) && (payloadlen != 0U)))
    {
        err = udif_error_logging_failure;
    }
    else
    {
        err = udif_event_create(&eventrec, (ledger == UDIF_LEDGER_MEMBERSHIP) ? udif_event_class_membership : ((ledger == UDIF_LEDGER_TRANSACTION) ? udif_event_class_transaction : udif_event_class_registry), eventcode, actorser, subjectser,
            contextid, timestamp, payload, payloadlen);

        if (err == udif_error_none)
        {
            err = udif_event_serialize(enc, sizeof(enc), &eventrec);
        }

        if (err == udif_error_none)
        {
            udif_mcel_set_active_ledger(mgr, ledger);

            outseq = 0U;

            if (udif_mcel_add_record(mgr, enc, sizeof(enc), false, &outseq) == false)
            {
                err = udif_error_logging_failure;
            }
        }

        udif_event_clear(&eventrec);
        qsc_memutils_secure_erase(enc, sizeof(enc));
    }

    return err;
}
